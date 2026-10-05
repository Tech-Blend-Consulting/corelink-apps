package transit

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// Envelope mode: the application takes ciphertext from a connector and the key
// from CoreLink, and opens the secret itself.
//
// Nothing between the two holds both halves. The connector is granted
// secrets:cache and keeps envelopes it cannot open; this application is granted
// secrets:unwrap and may open one it already has. A connector that is
// compromised holds ciphertext; a key intercepted on its way here opens the one
// secret it belongs to and nothing else, because the additional authenticated
// data binds each envelope to its own secret and version.
//
// Where the application has no route out, the unwrap call goes through the
// connector's CONNECT tunnel, so its TLS session still terminates at CoreLink.
// Set ConnectorProxy for that; the connector moves bytes it cannot read, and
// CoreLink sees this application as the caller rather than the connector.
//
// See docs/secret-delivery.md.

// ErrStaleEnvelope is a cached envelope the current key will not open.
//
// Told apart from a corrupt one on purpose. A rollback attempt and a damaged
// envelope look identical at the AEAD, and should not look identical in a log:
// the recovery for a stale one is to ask the connector again, and this is what
// says so.
var ErrStaleEnvelope = errors.New("the envelope held by the connector is not the current one")

// ErrEnvelopeCorrupt is an envelope that did not open and was not stale.
//
// The key belonged to the version the envelope claims, and it still failed, so
// the ciphertext or the tag has been altered. Refetching will not help and the
// application should not quietly retry.
var ErrEnvelopeCorrupt = errors.New("the envelope did not open with the key for its own version")

// ErrWrongSecret is a connector answering with a different secret than the one
// asked for.
//
// The case the version check cannot catch: an envelope is bound to its own id
// and version, so another secret's id and envelope together are internally
// consistent and open cleanly. Only the name tells them apart, and only CoreLink
// is authoritative about which name an id has.
var ErrWrongSecret = errors.New("the connector answered with a different secret")

// sealedEnvelope is what a connector serves and what CoreLink stores.
type sealedEnvelope struct {
	SecretID string `json:"secret_id"`
	Name     string `json:"name"`
	Version  int    `json:"version"`
	Envelope string `json:"envelope"`
}

// storedSecret is the record inside an envelope.
type storedSecret struct {
	Value string `json:"value"`
}

// envelopeBody is the AES-GCM payload as CoreLink writes it.
type envelopeBody struct {
	EncryptedData []byte `json:"encrypted_data"`
	Nonce         []byte `json:"nonce"`
	AAD           []byte `json:"aad,omitempty"`
}

// GetSecretSealed fetches a secret as ciphertext from the connector, asks
// CoreLink for the key, and opens it here.
//
// Requires secrets:unwrap on the secret, and a connector granted secrets:cache
// on it. The value exists in this process and nowhere else: no file, no
// Kubernetes Secret, nothing in the connector that can be read.
//
// A stale envelope is retried once, which is the case this is built for -- the
// connector holding a version CoreLink has since rotated past. The retry asks
// the connector to refetch, and if the second attempt fails the same way the
// error says stale rather than corrupt, because they are different problems.
func (c *Client) GetSecretSealed(name string) (string, error) {
	if c.url == "" {
		return "", fmt.Errorf("transit: GetSecretSealed needs a connector; set TransitURL")
	}
	if c.platformURL == "" || c.nhiID == "" {
		return "", fmt.Errorf("transit: GetSecretSealed needs an identity; set PlatformURL and NHIID")
	}

	value, err := c.openSealed(name, false)
	if !errors.Is(err, ErrStaleEnvelope) {
		return value, err
	}
	// Once, with the connector told to refetch.
	return c.openSealed(name, true)
}

// openSealed does one attempt.
func (c *Client) openSealed(name string, refresh bool) (string, error) {
	sealed, err := c.fetchEnvelope(name, refresh)
	if err != nil {
		return "", err
	}

	dek, version, authoritativeName, err := c.unwrapDEK(sealed.SecretID)
	if err != nil {
		return "", err
	}
	defer zero(dek)

	// The name CoreLink says this id belongs to must be the name that was asked
	// for.
	//
	// This is the substitution case the version check does not cover. The AAD
	// binds an envelope to its own id and version, so a connector that answered
	// with another secret's id and envelope produces a pair that is internally
	// consistent and opens cleanly -- under the wrong name. Only CoreLink knows
	// which name the id really has, and only the application knows which name it
	// wanted, so the comparison has to happen here.
	if authoritativeName != "" && authoritativeName != strings.Trim(name, "/") {
		return "", fmt.Errorf("%w: asked for %q and the connector answered with %q",
			ErrWrongSecret, strings.Trim(name, "/"), authoritativeName)
	}

	// The key belongs to whatever version CoreLink currently holds. A different
	// version means this envelope is behind, and saying so here is cheaper and
	// clearer than letting the AEAD fail for an unexplained reason.
	if version != sealed.Version {
		return "", fmt.Errorf("%w: the connector served version %d, CoreLink is on %d",
			ErrStaleEnvelope, sealed.Version, version)
	}

	plaintext, err := openEnvelope(sealed.Envelope, dek, sealed.SecretID, version)
	if errors.Is(err, errUnboundEnvelope) {
		// It opened, and it was sealed before binding existed. Reported rather
		// than passed over in silence: opening it is unavoidable, but it should
		// not look identical to one that is bound, or nobody ever learns there
		// is something to re-seal. Rotating the secret binds it.
		if c.onUnbound != nil {
			c.onUnbound(name)
		}
	} else if err != nil {
		return "", err
	}
	defer zero(plaintext)

	// The stored record wraps the value. Older records may be the bare value.
	//
	// A certificate bundle arrives here as that value: JSON inside the record.
	// GetCertificate parses it, which is why the connector no longer needs to
	// hold a readable bundle to serve its parts.
	var stored storedSecret
	if json.Unmarshal(plaintext, &stored) == nil && stored.Value != "" {
		return stored.Value, nil
	}
	return string(plaintext), nil
}

// fetchEnvelope takes the sealed envelope from the connector.
//
// Unauthenticated, because the connector has nothing to decide: what it serves
// cannot be opened without a grant CoreLink checks.
func (c *Client) fetchEnvelope(name string, refresh bool) (*sealedEnvelope, error) {
	path, err := envelopePath(name)
	if err != nil {
		return nil, err
	}
	endpoint := c.url + "/v1/envelopes/" + path
	if refresh {
		endpoint += "?refresh=1"
	}
	resp, err := c.httpClient.Get(endpoint)
	if err != nil {
		return nil, fmt.Errorf("transit: reaching the connector: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("transit: the connector has no envelope for %q (status %d: %s)",
			name, resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var sealed sealedEnvelope
	if err := json.NewDecoder(resp.Body).Decode(&sealed); err != nil {
		return nil, fmt.Errorf("transit: decoding the connector's response: %w", err)
	}
	if sealed.Envelope == "" || sealed.SecretID == "" {
		return nil, fmt.Errorf("transit: the connector served an incomplete envelope for %q", name)
	}
	return &sealed, nil
}

// unwrapDEK asks CoreLink for the key to one secret.
//
// CoreLink unwraps its own copy, so nothing this process holds takes part: an
// application handed somebody else's ciphertext cannot have it opened by naming
// a secret it is entitled to.
func (c *Client) unwrapDEK(secretID string) (dek []byte, version int, name string, err error) {
	endpoint := c.platformURL + "/api/v1/nhi-agent/secrets/" + url.PathEscape(secretID) + "/unwrap"
	req, err := http.NewRequest(http.MethodPost, endpoint, nil)
	if err != nil {
		return nil, 0, "", fmt.Errorf("transit: building the unwrap request: %w", err)
	}
	c.sessionMu.Lock()
	session := c.sessionID
	c.sessionMu.Unlock()
	if session == "" {
		return nil, 0, "", fmt.Errorf("transit: no CoreLink session; call Bootstrap first")
	}
	req.Header.Set("X-NHI-Session", session)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, 0, "", fmt.Errorf("transit: reaching CoreLink to unwrap: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, 0, "", fmt.Errorf("transit: CoreLink refused to unwrap (status %d: %s)",
			resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var out struct {
		Version int    `json:"version"`
		DEK     string `json:"dek"`
		// The name CoreLink says this id belongs to. Empty against a CoreLink
		// that predates sending it, in which case the substitution check is
		// skipped rather than failing every fetch.
		Name string `json:"name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, 0, "", fmt.Errorf("transit: decoding the key: %w", err)
	}
	key, err := base64.StdEncoding.DecodeString(out.DEK)
	if err != nil {
		return nil, 0, "", fmt.Errorf("transit: the key is not base64: %w", err)
	}
	if len(key) == 0 {
		return nil, 0, "", fmt.Errorf("transit: CoreLink returned no key")
	}
	return key, out.Version, out.Name, nil
}

// openEnvelope decrypts, requiring the stored AAD to be the one this secret and
// version imply.
//
// Rebuilding the expected value and comparing it is what turns tamper-evidence
// into binding. Decrypting with whatever AAD the envelope carries detects an
// altered envelope, because the tag breaks, but binds nothing: an envelope
// claiming to be some other secret would open happily.
func openEnvelope(sealedB64 string, dek []byte, secretID string, version int) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(sealedB64)
	if err != nil {
		return nil, fmt.Errorf("transit: the envelope is not base64: %w", err)
	}
	var body envelopeBody
	if err := json.Unmarshal(raw, &body); err != nil {
		return nil, fmt.Errorf("transit: the envelope is not an envelope: %w", err)
	}

	expected := secretAAD(secretID, version)

	// What the envelope was actually sealed under, which is what the cipher must
	// be given.
	//
	// A non-empty stored value must equal the one rebuilt from the authorized
	// context: that comparison is what turns tamper-evidence into binding, and
	// without it an envelope claiming to be some other secret would open happily.
	//
	// An empty one means the envelope predates binding, and every secret written
	// before that change is in exactly that state -- all twenty of production's
	// versions, when this was measured. Passing the rebuilt value to the cipher
	// anyway fails the tag and reports corruption, so no existing secret could be
	// delivered through the sealed path at all, and the failure named the one
	// thing the design says must never be confused with a rollback. The platform
	// already skips its own compare for these; this mirrors it.
	effective := expected
	unbound := len(body.AAD) == 0
	if unbound {
		effective = nil
	} else if !equalBytes(body.AAD, expected) {
		// Written for a different secret or a different version. Named as stale
		// rather than corrupt: the likely cause is a connector holding an old
		// envelope, and the recovery is to ask it again.
		return nil, fmt.Errorf("%w: it is bound to something other than %s version %d",
			ErrStaleEnvelope, secretID, version)
	}

	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, fmt.Errorf("transit: the key is not a usable AES key: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("transit: preparing AES-GCM: %w", err)
	}
	plaintext, err := gcm.Open(nil, body.Nonce, body.EncryptedData, effective)
	if err != nil {
		// The key was for the version the envelope claims and the binding
		// matched, so this is not a rollback: the ciphertext or the tag has been
		// altered. Refetching will not help.
		return nil, ErrEnvelopeCorrupt
	}
	if unbound {
		return plaintext, errUnboundEnvelope
	}
	return plaintext, nil
}

// errUnboundEnvelope is returned alongside the plaintext of an envelope that
// carried no binding. Not an error the caller sees: openSealed turns it into the
// OnUnboundEnvelope notification and drops it.
var errUnboundEnvelope = errors.New("transit: the envelope carried no binding")

// secretAAD is the additional authenticated data CoreLink seals a secret under.
//
// Must match crypto.SecretAAD on the platform exactly, byte for byte: the two
// are one wire format and changing either alone makes every envelope fail to
// open. The pair is covered by the delivery test in tests/e2e/delivery.
func secretAAD(secretID string, version int) []byte {
	return []byte(fmt.Sprintf("cl.secret.v1|%s|%d", secretID, version))
}

// envelopePath escapes a secret name for a URL while keeping its slashes, which
// are part of the name rather than a path structure.
//
// A "." or ".." segment is refused rather than escaped. Escaping it would be a
// pretence: HTTP clients and servers normalise dot segments in a path, so such a
// name would be asked for as a different one, and refusing is honest about the
// fact that no secret can be named that way anyway -- the platform's own path
// validation rejects "..".
func envelopePath(name string) (string, error) {
	trimmed := strings.Trim(name, "/")
	if trimmed == "" {
		return "", fmt.Errorf("transit: a secret name is required")
	}
	parts := strings.Split(trimmed, "/")
	for i, p := range parts {
		if p == "" {
			return "", fmt.Errorf("transit: %q has an empty path segment", name)
		}
		if p == "." || p == ".." {
			return "", fmt.Errorf("transit: %q is not a secret name", name)
		}
		parts[i] = url.PathEscape(p)
	}
	return strings.Join(parts, "/"), nil
}

// equalBytes is a plain comparison: both values are known to the holder of the
// envelope, so there is no secret here to leak through timing.
func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// zero overwrites a buffer once it is finished with.
//
// Worth doing and not worth overclaiming: Go may have copied the value
// elsewhere, and the string this function cannot reach is the one the
// application goes on to use. It narrows the window; it does not erase the
// value.
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// Certificate is a TLS bundle stored as a secret.
type Certificate struct {
	Certificate string `json:"certificate"`
	PrivateKey  string `json:"private_key"`
	CAChain     string `json:"ca_chain"`
}

// GetCertificate fetches a TLS bundle through the sealed path and parses it here.
//
// A certificate is a secret whose value happens to be a bundle, so it needs no
// delivery mechanism of its own: the same envelope, the same key, the same
// binding. The connector used to serve a bundle's parts from plaintext it held
// in memory, which was the last readable thing in that process; parsing here
// instead is what let that go.
//
// The private key exists in this process and nowhere else.
func (c *Client) GetCertificate(name string) (Certificate, error) {
	value, err := c.GetSecretSealed(name)
	if err != nil {
		return Certificate{}, err
	}

	var bundle Certificate
	if err := json.Unmarshal([]byte(value), &bundle); err != nil {
		return Certificate{}, fmt.Errorf("transit: %q is not a TLS certificate bundle: %w", name, err)
	}
	// Both halves, or it is not a usable bundle. A secret that merely happens to
	// be JSON should not come back as a certificate with empty fields.
	if bundle.Certificate == "" || bundle.PrivateKey == "" {
		return Certificate{}, fmt.Errorf("transit: %q carries no certificate and key", name)
	}
	return bundle, nil
}
