package transit

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// seal builds an envelope the way CoreLink does, so these tests exercise the
// real wire format rather than a convenient one.
func seal(t *testing.T, value, secretID string, version int, dek []byte) string {
	t.Helper()
	block, err := aes.NewCipher(dek)
	if err != nil {
		t.Fatalf("cipher: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("gcm: %v", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		t.Fatalf("nonce: %v", err)
	}
	aad := secretAAD(secretID, version)
	record, err := json.Marshal(storedSecret{Value: value})
	if err != nil {
		t.Fatalf("record: %v", err)
	}
	body, err := json.Marshal(envelopeBody{
		EncryptedData: gcm.Seal(nil, nonce, record, aad),
		Nonce:         nonce,
		AAD:           aad,
	})
	if err != nil {
		t.Fatalf("body: %v", err)
	}
	return base64.StdEncoding.EncodeToString(body)
}

func newDEK(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		t.Fatalf("key: %v", err)
	}
	return key
}

// fakePlatform serves the unwrap endpoint, returning the key for whichever
// secret was named -- which is the property the whole model rests on.
type fakePlatform struct {
	keys     map[string][]byte
	versions map[string]int
	// names is what CoreLink says each id is called, which is what lets the SDK
	// notice a connector answering with a different secret.
	names map[string]string
	// listing is what the secrets listing returns, for resolution.
	listing []map[string]string
	unwraps int
}

func (f *fakePlatform) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/nhi-agent/secrets" {
			rows := f.listing
			if rows == nil {
				rows = []map[string]string{}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": rows})
			return
		}
		if !strings.HasSuffix(r.URL.Path, "/unwrap") {
			http.NotFound(w, r)
			return
		}
		f.unwraps++
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		id := parts[len(parts)-2]
		key, ok := f.keys[id]
		if !ok {
			http.Error(w, `{"error":{"code":"NOT_FOUND"}}`, http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"secret_id": id,
			// CoreLink is authoritative about which name an id has.
			"name":    f.names[id],
			"version": f.versions[id],
			"dek":     base64.StdEncoding.EncodeToString(key),
		})
	})
}

// fakeConnector serves envelopes by name, counting refresh requests.
type fakeConnector struct {
	envelopes map[string]sealedEnvelope
	refreshes int
	// onRefresh replaces what is served once a refresh is asked for, standing in
	// for a connector catching up with a rotation.
	onRefresh map[string]sealedEnvelope
}

// A plain handler rather than a ServeMux pattern. This module declares go 1.21,
// which predates the enhanced patterns, so "GET /v1/envelopes/{name...}" would
// be matched as a literal path and every request would 404 -- quietly, since
// nothing warns about it. The connector serves that route from the main module,
// where the patterns work.
func (f *fakeConnector) handler() http.Handler {
	const prefix = "/v1/envelopes/"
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || !strings.HasPrefix(r.URL.Path, prefix) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		name := strings.Trim(strings.TrimPrefix(r.URL.Path, prefix), "/")
		if r.URL.Query().Get("refresh") != "" {
			f.refreshes++
			if updated, ok := f.onRefresh[name]; ok {
				f.envelopes[name] = updated
			}
		}
		env, ok := f.envelopes[name]
		if !ok {
			http.Error(w, "no envelope for that name", http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(env)
	})
}

// clientFor wires a client to a fake connector and platform with a session in
// place, as Bootstrap would leave it.
func clientFor(t *testing.T, connectorURL, platformURL string) *Client {
	t.Helper()
	c := New(Options{
		TransitURL:  connectorURL,
		PlatformURL: platformURL,
		NHIID:       "11111111-1111-1111-1111-111111111111",
	})
	c.sessionID = "session-in-place"
	return c
}

func TestGetSecretSealedOpensWhatTheConnectorServes(t *testing.T) {
	dek := newDEK(t)
	const id = "secret-one"

	conn := &fakeConnector{envelopes: map[string]sealedEnvelope{
		"production/dbone": {
			SecretID: id, Name: "production/dbone", Version: 3,
			Envelope: seal(t, "the-one-true-password", id, 3, dek),
		},
	}}
	plat := &fakePlatform{
		keys:     map[string][]byte{id: dek},
		versions: map[string]int{id: 3},
	}

	connSrv := httptest.NewServer(conn.handler())
	defer connSrv.Close()
	platSrv := httptest.NewServer(plat.handler())
	defer platSrv.Close()

	c := clientFor(t, connSrv.URL, platSrv.URL)
	got, err := c.GetSecretSealed("production/dbone")
	if err != nil {
		t.Fatalf("GetSecretSealed: %v", err)
	}
	if got != "the-one-true-password" {
		t.Errorf("got %q, want the stored value", got)
	}
	if plat.unwraps != 1 {
		t.Errorf("unwraps = %d, want one key fetch", plat.unwraps)
	}
}

// Another secret's key must not open this envelope, even when the caller is
// entitled to both. This is the case authorization cannot catch.
func TestAnotherSecretsKeyDoesNotOpenThisEnvelope(t *testing.T) {
	dekOne, dekTwo := newDEK(t), newDEK(t)

	conn := &fakeConnector{envelopes: map[string]sealedEnvelope{
		// The connector serves secret one's envelope, but names secret two's id.
		// A platform that unwrapped whatever ciphertext it was handed would
		// return a key that opens this; one that unwraps its own copy of the
		// secret that was named returns a key that does not.
		"production/dbone": {
			SecretID: "secret-two", Name: "production/dbone", Version: 1,
			Envelope: seal(t, "the-one-true-password", "secret-one", 1, dekOne),
		},
	}}
	plat := &fakePlatform{
		keys:     map[string][]byte{"secret-two": dekTwo},
		versions: map[string]int{"secret-two": 1},
	}

	connSrv := httptest.NewServer(conn.handler())
	defer connSrv.Close()
	platSrv := httptest.NewServer(plat.handler())
	defer platSrv.Close()

	c := clientFor(t, connSrv.URL, platSrv.URL)
	got, err := c.GetSecretSealed("production/dbone")
	if err == nil {
		t.Fatalf("another secret's key opened this envelope, returning %q", got)
	}
	// Caught on the binding before the key is even tried, because the stored AAD
	// names secret one and the authorized context names secret two.
	if !errors.Is(err, ErrStaleEnvelope) {
		t.Errorf("error was %v, want it identified as not belonging to this secret", err)
	}
}

func TestAStaleEnvelopeIsRetriedOnceAndThenNamed(t *testing.T) {
	dek := newDEK(t)
	const id = "secret-one"

	t.Run("a refresh that catches up succeeds", func(t *testing.T) {
		conn := &fakeConnector{
			envelopes: map[string]sealedEnvelope{
				// Behind: sealed at version 2 while CoreLink is on 3.
				"production/dbone": {
					SecretID: id, Version: 2,
					Envelope: seal(t, "old-password", id, 2, dek),
				},
			},
			onRefresh: map[string]sealedEnvelope{
				"production/dbone": {
					SecretID: id, Version: 3,
					Envelope: seal(t, "new-password", id, 3, dek),
				},
			},
		}
		plat := &fakePlatform{keys: map[string][]byte{id: dek}, versions: map[string]int{id: 3}}

		connSrv := httptest.NewServer(conn.handler())
		defer connSrv.Close()
		platSrv := httptest.NewServer(plat.handler())
		defer platSrv.Close()

		c := clientFor(t, connSrv.URL, platSrv.URL)
		got, err := c.GetSecretSealed("production/dbone")
		if err != nil {
			t.Fatalf("a stale envelope was not recovered: %v", err)
		}
		if got != "new-password" {
			t.Errorf("got %q, want the current value", got)
		}
		if conn.refreshes != 1 {
			t.Errorf("refreshes = %d, want exactly one", conn.refreshes)
		}
	})

	t.Run("a connector that stays behind is reported as stale, not corrupt", func(t *testing.T) {
		// Different problems with different recoveries, so they must not look
		// the same to whoever reads the log.
		conn := &fakeConnector{envelopes: map[string]sealedEnvelope{
			"production/dbone": {
				SecretID: id, Version: 2,
				Envelope: seal(t, "old-password", id, 2, dek),
			},
		}}
		plat := &fakePlatform{keys: map[string][]byte{id: dek}, versions: map[string]int{id: 3}}

		connSrv := httptest.NewServer(conn.handler())
		defer connSrv.Close()
		platSrv := httptest.NewServer(plat.handler())
		defer platSrv.Close()

		c := clientFor(t, connSrv.URL, platSrv.URL)
		_, err := c.GetSecretSealed("production/dbone")
		if !errors.Is(err, ErrStaleEnvelope) {
			t.Errorf("error was %v, want ErrStaleEnvelope", err)
		}
		if conn.refreshes != 1 {
			t.Errorf("refreshes = %d, want one retry and no more", conn.refreshes)
		}
	})
}

func TestAnAlteredEnvelopeIsReportedAsCorrupt(t *testing.T) {
	dek := newDEK(t)
	const id = "secret-one"

	sealedB64 := seal(t, "the-one-true-password", id, 1, dek)
	raw, err := base64.StdEncoding.DecodeString(sealedB64)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	var body envelopeBody
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	// Flip a ciphertext bit, leaving the binding intact. Refetching cannot fix
	// this, so it must not be reported as something a refetch would fix.
	body.EncryptedData[0] ^= 0xff
	altered, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	conn := &fakeConnector{envelopes: map[string]sealedEnvelope{
		"production/dbone": {
			SecretID: id, Version: 1,
			Envelope: base64.StdEncoding.EncodeToString(altered),
		},
	}}
	plat := &fakePlatform{keys: map[string][]byte{id: dek}, versions: map[string]int{id: 1}}

	connSrv := httptest.NewServer(conn.handler())
	defer connSrv.Close()
	platSrv := httptest.NewServer(plat.handler())
	defer platSrv.Close()

	c := clientFor(t, connSrv.URL, platSrv.URL)
	if _, err := c.GetSecretSealed("production/dbone"); !errors.Is(err, ErrEnvelopeCorrupt) {
		t.Errorf("error was %v, want ErrEnvelopeCorrupt", err)
	}
	if conn.refreshes != 0 {
		t.Errorf("refreshes = %d, want none: a refetch cannot repair altered ciphertext", conn.refreshes)
	}
}

func TestOnlyPlatformCallsGoThroughTheConnectorTunnel(t *testing.T) {
	// The tunnel reaches the platform and nothing else, so sending the
	// connector's own endpoints through it would have them refused. Proven by
	// pointing the proxy at a recorder and checking what it is asked for.
	var proxied []string
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxied = append(proxied, r.Host)
		http.Error(w, "recorded", http.StatusBadGateway)
	}))
	defer proxy.Close()

	c := New(Options{
		TransitURL: "http://127.0.0.1:9092",
		// https, because that is the only scheme a CONNECT tunnel can carry.
		PlatformURL:    "https://platform.invalid:8443",
		NHIID:          "11111111-1111-1111-1111-111111111111",
		ConnectorProxy: strings.TrimPrefix(proxy.URL, "http://"),
	})
	c.sessionID = "session-in-place"

	// A platform call: must be proxied.
	if _, _, _, err := c.unwrapDEK("secret-one"); err == nil {
		t.Error("the recorder answered 502 and the call reported success")
	}
	if len(proxied) != 1 || !strings.Contains(proxied[0], "platform.invalid") {
		t.Errorf("proxied = %v, want the platform call to have gone through the tunnel", proxied)
	}

	// A connector call: must not be. It will fail to connect, which is the
	// point -- it was attempted directly rather than through the proxy.
	before := len(proxied)
	_, _ = c.fetchEnvelope("production/dbone", false)
	if len(proxied) != before {
		t.Errorf("proxied = %v, want the connector call not to have been tunnelled", proxied)
	}
}

func TestGetSecretSealedRequiresAConnectorAndAnIdentity(t *testing.T) {
	cases := []struct {
		name string
		opts Options
		want string
	}{
		{"no connector", Options{PlatformURL: "http://p", NHIID: "x"}, "connector"},
		{"no platform", Options{TransitURL: "http://c", NHIID: "x"}, "identity"},
		{"no identity", Options{TransitURL: "http://c", PlatformURL: "http://p"}, "identity"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := New(tc.opts).GetSecretSealed("production/dbone")
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error was %v, want it to mention %q", err, tc.want)
			}
		})
	}
}

func TestEnvelopePathKeepsSlashesAndEscapesSegments(t *testing.T) {
	// A secret name has slashes in it, and they are part of the name rather than
	// a path structure, so they survive while everything else is escaped.
	cases := map[string]string{
		"production/dbone":   "production/dbone",
		"/production/dbone/": "production/dbone",
		"prod/db one":        "prod/db%20one",
		"prod/a?b":           "prod/a%3Fb",
	}
	for in, want := range cases {
		got, err := envelopePath(in)
		if err != nil {
			t.Errorf("envelopePath(%q): %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("envelopePath(%q) = %q, want %q", in, got, want)
		}
	}

	t.Run("a dot segment is refused rather than escaped", func(t *testing.T) {
		// Escaping would be a pretence: clients and servers normalise dot
		// segments, so the name asked for would not be the name given.
		for _, bad := range []string{"prod/../etc/passwd", "prod/.", "..", "prod//dbone", "", "/"} {
			if got, err := envelopePath(bad); err == nil {
				t.Errorf("envelopePath(%q) = %q, want it refused", bad, got)
			}
		}
	})
}

// The AAD format is one wire format shared with the platform. If this changes,
// internal/crypto.SecretAAD must change with it or every envelope stops opening.
func TestTheAADFormatIsFixed(t *testing.T) {
	got := string(secretAAD("6edba51b-0ad8-4e0c-afbe-8cf5c336ce8f", 3))
	want := "cl.secret.v1|6edba51b-0ad8-4e0c-afbe-8cf5c336ce8f|3"
	if got != want {
		t.Errorf("secretAAD = %q, want %q (and internal/crypto.SecretAAD must agree byte for byte)", got, want)
	}
	fmt.Fprintln(io.Discard, got)
}

// A plain-http platform cannot be tunnelled, and the SDK says so.
//
// Go only issues CONNECT for an https target. An http one is sent through the
// proxy as an ordinary request, which the connector could read in full -- the
// arrangement the tunnel exists to avoid. Measured, not assumed: the connector
// answers 405, and this turns that into an explanation.
func TestAPlainHTTPPlatformCannotBeTunnelled(t *testing.T) {
	var proxied int
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxied++
		http.Error(w, "should not have been reached", http.StatusBadGateway)
	}))
	defer proxy.Close()

	c := New(Options{
		TransitURL:     "http://127.0.0.1:9092",
		PlatformURL:    "http://platform.invalid:8080",
		NHIID:          "11111111-1111-1111-1111-111111111111",
		ConnectorProxy: strings.TrimPrefix(proxy.URL, "http://"),
	})
	c.sessionID = "session-in-place"

	_, _, _, err := c.unwrapDEK("secret-one")
	if err == nil {
		t.Fatal("a plain-http platform call through the tunnel reported success")
	}
	if !strings.Contains(err.Error(), "https") {
		t.Errorf("error was %v, want it to name the scheme as the problem", err)
	}
	if proxied != 0 {
		t.Errorf("the request reached the proxy %d times; it must not be sent in the clear", proxied)
	}
}

// loadFixture reads one of the platform-produced fixtures.
func loadFixture(t *testing.T, name string) (sealedEnvelope, []byte, string) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "testdata", name))
	if err != nil {
		t.Fatalf("reading %s: %v", name, err)
	}
	var fx struct {
		SecretID      string `json:"secret_id"`
		Version       int    `json:"version"`
		Envelope      string `json:"envelope"`
		DEK           string `json:"dek"`
		ExpectedValue string `json:"expected_value"`
	}
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatalf("parsing %s: %v", name, err)
	}
	dek, err := base64.StdEncoding.DecodeString(fx.DEK)
	if err != nil {
		t.Fatalf("the fixture key is not base64: %v", err)
	}
	return sealedEnvelope{
		SecretID: fx.SecretID,
		Version:  fx.Version,
		Envelope: fx.Envelope,
	}, dek, fx.ExpectedValue
}

// A certificate is a secret whose value is a bundle, so it comes back one level
// deeper than a password: the record wraps the bundle JSON as a string.
//
// That nesting is where a bug hides. An SDK that returned the record rather than
// its value would look correct on a password and produce an empty certificate
// here, which is why this runs against a fixture the platform sealed rather than
// against a bundle made up locally.
func TestGetCertificateParsesTheBundleInsideTheRecord(t *testing.T) {
	env, dek, expectedBundle := loadFixture(t, "sealed_certificate.json")

	conn := &fakeConnector{envelopes: map[string]sealedEnvelope{"production/web-tls": env}}
	plat := &fakePlatform{
		keys:     map[string][]byte{env.SecretID: dek},
		versions: map[string]int{env.SecretID: env.Version},
	}
	connSrv := httptest.NewServer(conn.handler())
	defer connSrv.Close()
	platSrv := httptest.NewServer(plat.handler())
	defer platSrv.Close()

	c := clientFor(t, connSrv.URL, platSrv.URL)

	t.Run("the bundle's parts come out", func(t *testing.T) {
		cert, err := c.GetCertificate("production/web-tls")
		if err != nil {
			t.Fatalf("GetCertificate: %v", err)
		}
		if !strings.Contains(cert.Certificate, "BEGIN CERTIFICATE") {
			t.Errorf("certificate = %q, want a PEM certificate", cert.Certificate)
		}
		if !strings.Contains(cert.PrivateKey, "BEGIN PRIVATE KEY") {
			t.Errorf("private key = %q, want a PEM key", cert.PrivateKey)
		}
		if !strings.Contains(cert.CAChain, "BEGIN CERTIFICATE") {
			t.Errorf("ca chain = %q, want a PEM chain", cert.CAChain)
		}
	})

	t.Run("it is the bundle the platform sealed", func(t *testing.T) {
		// Compared against the fixture's own expected value, so a bundle that
		// parses but has lost a field does not pass.
		var want Certificate
		if err := json.Unmarshal([]byte(expectedBundle), &want); err != nil {
			t.Fatalf("the fixture's bundle is not a bundle: %v", err)
		}
		got, err := c.GetCertificate("production/web-tls")
		if err != nil {
			t.Fatalf("GetCertificate: %v", err)
		}
		if got != want {
			t.Errorf("got %+v, want %+v", got, want)
		}
	})

	t.Run("a secret that is not a bundle is refused", func(t *testing.T) {
		// A password is JSON-shaped once unwrapped in some deployments, and an
		// empty Certificate returned as success would be worse than an error.
		pwEnv, pwDek, _ := loadFixture(t, "sealed_envelope.json")
		conn.envelopes["production/dbone"] = pwEnv
		plat.keys[pwEnv.SecretID] = pwDek
		plat.versions[pwEnv.SecretID] = pwEnv.Version

		if cert, err := c.GetCertificate("production/dbone"); err == nil {
			t.Errorf("a password came back as a certificate: %+v", cert)
		}
	})
}

// A secret sealed before the AAD existed must still open.
//
// Every secret written before binding was added carries no AAD -- all twenty of
// production's versions, when this was measured. The platform still opens them,
// because its compare is skipped when nothing was stored. An SDK that passed the
// rebuilt AAD to the cipher anyway would fail the tag and report the one thing
// the design says must never be confused with a rollback: corruption.
func TestAPreAADEnvelopeOpensAndIsNotCalledCorrupt(t *testing.T) {
	env, dek, expectedValue := loadFixture(t, "sealed_legacy_no_aad.json")

	conn := &fakeConnector{envelopes: map[string]sealedEnvelope{"legacy/dbone": env}}
	plat := &fakePlatform{
		keys:     map[string][]byte{env.SecretID: dek},
		versions: map[string]int{env.SecretID: env.Version},
	}
	connSrv := httptest.NewServer(conn.handler())
	defer connSrv.Close()
	platSrv := httptest.NewServer(plat.handler())
	defer platSrv.Close()

	c := clientFor(t, connSrv.URL, platSrv.URL)

	var unbound []string
	c.onUnbound = func(name string) { unbound = append(unbound, name) }

	got, err := c.GetSecretSealed("legacy/dbone")
	if err != nil {
		t.Fatalf("a pre-AAD secret could not be delivered through the sealed path: %v", err)
	}
	if got != expectedValue {
		t.Errorf("got %q, want %q", got, expectedValue)
	}

	t.Run("and it is reported as unbound rather than passing silently", func(t *testing.T) {
		// Opening it is unavoidable -- it was sealed without binding -- but it
		// should not look the same as one that is bound, or nobody ever learns
		// there is something to re-seal.
		if len(unbound) != 1 || unbound[0] != "legacy/dbone" {
			t.Errorf("unbound = %v, want the one name reported once", unbound)
		}
	})
}

// A compromised connector cannot answer with a different secret.
//
// The case the version check and the AAD cannot catch between them. An envelope
// is bound to its own id and version, so another secret's id and envelope
// together are internally consistent: the key CoreLink returns for that id opens
// that envelope cleanly. What is wrong is the name -- the application asked for
// one secret and got another it also happens to hold unwrap on.
//
// Only CoreLink is authoritative about which name an id has, so it now sends the
// name with the key and the SDK compares it to what it asked for.
func TestASubstitutedSecretIsRefused(t *testing.T) {
	dekOne, dekTwo := newDEK(t), newDEK(t)
	const idOne, idTwo = "secret-one", "secret-two"

	conn := &fakeConnector{envelopes: map[string]sealedEnvelope{
		// The application asks for dbone; the connector answers with dbtwo's id
		// and dbtwo's envelope, consistently.
		"production/dbone": {
			SecretID: idTwo, Name: "production/dbtwo", Version: 1,
			Envelope: seal(t, "the-other-password", idTwo, 1, dekTwo),
		},
		"production/dbtwo": {
			SecretID: idTwo, Name: "production/dbtwo", Version: 1,
			Envelope: seal(t, "the-other-password", idTwo, 1, dekTwo),
		},
	}}
	plat := &fakePlatform{
		keys:     map[string][]byte{idOne: dekOne, idTwo: dekTwo},
		versions: map[string]int{idOne: 1, idTwo: 1},
		names:    map[string]string{idOne: "production/dbone", idTwo: "production/dbtwo"},
	}

	connSrv := httptest.NewServer(conn.handler())
	defer connSrv.Close()
	platSrv := httptest.NewServer(plat.handler())
	defer platSrv.Close()

	c := clientFor(t, connSrv.URL, platSrv.URL)

	t.Run("the substitution is refused", func(t *testing.T) {
		got, err := c.GetSecretSealed("production/dbone")
		if err == nil {
			t.Fatalf("a request for production/dbone was answered with another secret: %q", got)
		}
		if !errors.Is(err, ErrWrongSecret) {
			t.Errorf("error was %v, want ErrWrongSecret", err)
		}
	})

	t.Run("and the secret it really is still opens under its own name", func(t *testing.T) {
		// The check must not refuse honest answers.
		got, err := c.GetSecretSealed("production/dbtwo")
		if err != nil {
			t.Fatalf("GetSecretSealed: %v", err)
		}
		if got != "the-other-password" {
			t.Errorf("got %q, want the stored value", got)
		}
	})

	t.Run("a CoreLink that sends no name does not break the fetch", func(t *testing.T) {
		// Older platforms do not send it. The substitution check is skipped
		// rather than failing every fetch, because refusing to deliver anything
		// would be worse than the gap it closes.
		plat.names = nil
		if _, err := c.GetSecretSealed("production/dbtwo"); err != nil {
			t.Errorf("GetSecretSealed against a platform with no name: %v", err)
		}
	})
}

// Resolve must be able to fail in connector mode, which is the mode the
// delivery model is about.
//
// It returned nil immediately whenever a connector was configured, so the
// startup check an application was told to rely on could not fail and a missing
// grant surfaced at run time instead -- the thing it exists to prevent.
func TestResolveFailsInConnectorMode(t *testing.T) {
	env, dek, _ := loadFixture(t, "sealed_envelope.json")

	conn := &fakeConnector{envelopes: map[string]sealedEnvelope{"production/dbone": env}}
	plat := &fakePlatform{
		keys:     map[string][]byte{env.SecretID: dek},
		versions: map[string]int{env.SecretID: env.Version},
		names:    map[string]string{env.SecretID: "production/dbone"},
		// What the identity's grants cover, which is what resolution reads.
		listing: []map[string]string{
			{"id": env.SecretID, "name": "production/dbone"},
			{"id": "secret-two", "name": "production/uncached"},
		},
	}

	connSrv := httptest.NewServer(conn.handler())
	defer connSrv.Close()
	platSrv := httptest.NewServer(plat.handler())
	defer platSrv.Close()

	c := clientFor(t, connSrv.URL, platSrv.URL)

	t.Run("a name the identity has no grant for fails", func(t *testing.T) {
		err := c.Resolve("production/dbone", "production/not-granted")
		if err == nil {
			t.Fatal("Resolve passed for a name the identity cannot have")
		}
		if !strings.Contains(err.Error(), "not-granted") {
			t.Errorf("error %v does not name the missing secret", err)
		}
	})

	t.Run("a name no connector caches fails too", func(t *testing.T) {
		// Granted to unwrap but absent from the connector: just as broken at run
		// time, and the point is to find it at deploy time.
		err := c.Resolve("production/uncached")
		if err == nil {
			t.Fatal("Resolve passed for a name the connector holds no envelope for")
		}
		if !strings.Contains(err.Error(), "uncached") {
			t.Errorf("error %v does not name the uncached secret", err)
		}
	})

	t.Run("and it passes when everything is in place", func(t *testing.T) {
		if err := c.Resolve("production/dbone"); err != nil {
			t.Errorf("Resolve: %v", err)
		}
	})
}
