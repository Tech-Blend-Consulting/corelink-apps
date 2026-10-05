// Package transit provides a client for the Tech Blend Transit API.
//
// Authentication is via NHI (Non-Human Identity) passwordless attestation.
// The client derives a runtime fingerprint (binary hash + machine ID + hostname)
// and exchanges it for an opaque session ID via the platform's NHI connect
// endpoint. A background goroutine heartbeats every 50 minutes to keep the
// session alive and reconnects automatically on expiry.
//
// Supply Options.NHIID and Options.PlatformURL, then call Bootstrap() before
// making any API calls.
package transit

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// Options configures a Client.
// collectAttestation asks the caller first, and falls back to detection.
//
// A workload that federates to its own issuer knows how to get its token and the
// SDK does not; a pod or a host is the other way round.
func (c *Client) collectAttestation() (string, string, error) {
	if c.attest != nil {
		return c.attest()
	}
	return CollectAttestation(c.nhiID)
}

// AttestFunc returns the attestation type and evidence to present at connect.
// See Options.Attest.
type AttestFunc func() (attestType, evidence string, err error)

type Options struct {
	// TransitURL is the base URL of a transit agent. Leave it empty to talk to
	// the platform directly, which is the ordinary arrangement: there is then
	// nothing beside the application holding its secrets. An agent is for an
	// application with no route out, or a host where sharing one session across
	// several processes is worth a component.
	TransitURL string
	// PlatformURL is the base URL of the Tech Blend platform, used for NHI
	// connect and heartbeat calls. Required when NHIID is set.
	PlatformURL string
	// NHIID is the NHI identity ID for passwordless fingerprint-based auth.
	NHIID string
	// HTTPTimeout overrides the default 10s per-request timeout.
	HTTPTimeout time.Duration
	// CACertFile is the path to the transit agent CA certificate for HTTPS
	// verification. When non-empty, the client pins TLS verification to this CA.
	CACertFile string
	// Attest supplies the attestation to present, instead of the SDK detecting
	// one.
	//
	// For a workload that runs nowhere the SDK can recognise -- a SaaS product
	// with no connector, no pod and no instance identity document -- and
	// federates to its own OIDC issuer instead. Return ("oidc", <the token>).
	//
	// A function rather than a string, because these tokens are short lived by
	// design. The SDK calls it on every connect and reconnect, so a session that
	// drops at three in the morning re-mints rather than replaying something
	// that expired hours ago.
	//
	// Nothing in what it returns authorises anything: CoreLink verifies the
	// token against the issuer pinned to this identity, and the grant decides
	// what the identity may do.
	Attest AttestFunc
	// OnUnboundEnvelope is called when a secret opens from an envelope that
	// carried no binding, which is how every secret written before binding
	// existed is stored. Optional; the secret is returned either way, because
	// the alternative is that it cannot be fetched at all. Hook it to a log and
	// the names that appear are the ones to rotate.
	OnUnboundEnvelope func(name string)
	// ConnectorProxy is the connector's CONNECT tunnel, for an application with
	// no route out of its network: "127.0.0.1:9091", or wherever the connector
	// serves it.
	//
	// Only calls to PlatformURL go through it. The TLS session still terminates
	// at CoreLink, so the connector moves bytes it cannot read and CoreLink sees
	// this application as the caller -- which is the identity that should be
	// authorized. Calls to the connector itself are local and are not proxied
	// through it, and the tunnel would refuse them anyway: it reaches the
	// platform and nothing else.
	ConnectorProxy string
}

// Secret represents a single secret returned by the transit API.
type Secret struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Config represents a rendered config file returned by the transit API.
type Config struct {
	Name     string `json:"name"`
	FileName string `json:"file_name"`
	Content  string `json:"content"`
}

// Client is a thread-safe Transit API client.
type Client struct {
	opts options
	url  string

	// NHI session fields. sessionMu guards sessionID exclusively.
	nhiID       string
	attest      AttestFunc
	platformURL string
	// names maps configured secret names to platform ids, resolved once in
	// direct mode. See direct.go.
	names     nameIndex
	sessionID string
	sessionMu sync.Mutex

	stopCh     chan struct{}
	httpClient *http.Client

	// renewFloor overrides KeepAlive's minimum interval. Zero means the default;
	// only tests set it.
	renewFloor time.Duration
	// onUnbound is Options.OnUnboundEnvelope.
	onUnbound func(name string)
}

// hostOf is the hostname of a URL, or "" when it cannot be parsed.
func hostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

// options mirrors Options but with computed defaults applied.
type options struct {
	Options
}

// New creates a new Transit API client.
func New(opts Options) *Client {
	timeout := opts.HTTPTimeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	opts.HTTPTimeout = timeout

	transport := &http.Transport{}
	if opts.CACertFile != "" {
		caCert, err := os.ReadFile(opts.CACertFile)
		if err == nil {
			pool := x509.NewCertPool()
			if pool.AppendCertsFromPEM(caCert) {
				transport.TLSClientConfig = &tls.Config{RootCAs: pool}
			}
		}
	}
	if proxy := strings.TrimSpace(opts.ConnectorProxy); proxy != "" {
		platformHost := hostOf(opts.PlatformURL)
		proxyURL := &url.URL{Scheme: "http", Host: proxy}
		// Per request, so only the platform is tunnelled. Returning the proxy for
		// everything would send the connector's own endpoints through it, and the
		// tunnel permits one destination, so those would be refused.
		transport.Proxy = func(r *http.Request) (*url.URL, error) {
			if platformHost == "" || r.URL.Hostname() != platformHost {
				return nil, nil
			}
			// The tunnel carries CONNECT, and Go only issues CONNECT for an
			// https target: an http one goes through a proxy as an ordinary
			// request, in the clear, with the proxy able to read all of it. That
			// is the arrangement the tunnel exists to avoid, so the connector
			// refuses it -- and refusing here says why, rather than leaving a 405
			// to be explained.
			if r.URL.Scheme != "https" {
				return nil, fmt.Errorf(
					"transit: ConnectorProxy needs an https PlatformURL (got %q): the tunnel carries CONNECT, "+
						"and an http request would be sent through the connector in the clear instead", r.URL.Scheme)
			}
			return proxyURL, nil
		}
	}
	httpClient := &http.Client{Timeout: timeout, Transport: transport}

	c := &Client{
		opts:        options{opts},
		url:         strings.TrimRight(opts.TransitURL, "/"),
		nhiID:       opts.NHIID,
		attest:      opts.Attest,
		platformURL: strings.TrimRight(opts.PlatformURL, "/"),
		stopCh:      make(chan struct{}),
		httpClient:  httpClient,
		onUnbound:   opts.OnUnboundEnvelope,
	}

	return c
}

// Bootstrap authenticates the client via NHI fingerprint connect and starts
// the background heartbeat loop.
func (c *Client) Bootstrap() error {
	return c.nhiConnect()
}

// ListSecrets returns the secrets available to this client.
//
// Direct mode lists what this identity's grants cover. With a connector there is
// no listing to give: the connector holds envelopes, serves them by name, and
// deliberately offers no way to enumerate them -- an application asks for what
// it was configured to ask for. Resolve is how a configured list is checked at
// startup.
func (c *Client) ListSecrets() ([]Secret, error) {
	if c.directMode() {
		return c.listSecretsDirect()
	}
	return nil, fmt.Errorf("transit: a connector serves envelopes by name and offers no listing; " +
		"name the secrets this application needs and check them with Resolve")
}

// GetSecret returns the value of a single secret by name.
//
// Direct mode fetches it from CoreLink under secrets:read. With a connector it
// is the sealed path: ciphertext from the connector, the key from CoreLink under
// this application's secrets:unwrap, opened here. Both end in a value held only
// by this process; the difference is what sits in between and what that thing
// could read.
//
// It used to ask the connector for plaintext. That endpoint is gone, and this
// method goes the sealed way rather than failing, so an application that already
// calls GetSecret needs no change.
func (c *Client) GetSecret(name string) (string, error) {
	if c.directMode() {
		return c.getSecretDirect(name)
	}
	return c.GetSecretSealed(name)
}

// ListConfigs returns all rendered config files accessible to this client.
func (c *Client) ListConfigs() ([]Config, error) {
	resp, err := c.authedGet(c.url + "/v1/configs")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("transit: list configs: HTTP %d: %s", resp.StatusCode, body)
	}
	var data struct {
		Configs []Config `json:"configs"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, fmt.Errorf("transit: decode configs: %w", err)
	}
	return data.Configs, nil
}

// GetConfig returns the rendered content of a single config file by name.
func (c *Client) GetConfig(name string) (string, error) {
	resp, err := c.authedGet(c.url + "/v1/configs/" + name)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("transit: get config %q: HTTP %d: %s", name, resp.StatusCode, body)
	}
	var data struct {
		Content string `json:"content"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return "", fmt.Errorf("transit: decode config: %w", err)
	}
	return data.Content, nil
}

// Close stops all background goroutines and sends a best-effort disconnect to
// the platform so the session is invalidated server-side rather than waiting
// for the idle timeout.
func (c *Client) Close() {
	select {
	case <-c.stopCh:
	default:
		close(c.stopCh)
	}

	c.sessionMu.Lock()
	hasSession := c.sessionID != ""
	c.sessionMu.Unlock()
	if hasSession {
		c.nhiDisconnect()
	}
}

// ------------------------------------------------------------------ NHI mode

// nhiConnect authenticates with the platform via attestation evidence.
// The environment is auto-detected (Kubernetes service account token, or host
// fingerprint as fallback). On success it stores the returned session ID and
// starts the heartbeat loop.
func (c *Client) nhiConnect() error {
	attestType, evidence, err := c.collectAttestation()
	if err != nil {
		return fmt.Errorf("transit: collect attestation: %w", err)
	}

	// Collect metadata for the admin approval UI.
	_, meta, _ := ComputeFingerprint(c.nhiID)
	meta["agent_type"] = "sdk-client"

	// evidence must not be logged -- it may contain a Kubernetes SA token.
	body, _ := json.Marshal(map[string]interface{}{
		"nhi_id": c.nhiID,
		"attestation": map[string]string{
			"type":     attestType,
			"evidence": evidence,
		},
		"metadata": meta,
	})

	resp, err := c.httpClient.Post(
		c.platformURL+"/api/v1/nhi-agent/connect",
		"application/json",
		bytes.NewReader(body),
	)
	if err != nil {
		return fmt.Errorf("transit: nhi connect request: %w", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return fmt.Errorf("transit: nhi connect failed: HTTP %d", resp.StatusCode)
	}

	var data struct {
		SessionID string `json:"session_id"`
		Status    string `json:"status"`
		ExpiresAt string `json:"expires_at"`
	}
	if err := json.Unmarshal(respBody, &data); err != nil {
		return fmt.Errorf("transit: decode nhi connect response: %w", err)
	}
	if data.SessionID == "" {
		return fmt.Errorf("transit: nhi connect: empty session_id in response")
	}

	// Treat a missing status field as "active" for backward compatibility.
	status := data.Status
	if status == "" {
		status = "active"
	}

	if status == "pending_approval" {
		prefix := data.SessionID
		if len(prefix) > 8 {
			prefix = prefix[:8]
		}
		log.Printf("Waiting for admin approval (session: %s)...", prefix)
		if err := c.pollApproval(data.SessionID); err != nil {
			return fmt.Errorf("transit: nhi connect: %w", err)
		}
	} else if status != "active" {
		return fmt.Errorf("transit: nhi connect: unexpected status %q", status)
	}

	c.sessionMu.Lock()
	c.sessionID = data.SessionID
	c.sessionMu.Unlock()

	go c.nhiRefreshLoop()
	return nil
}

// pollApproval polls the platform every 5 seconds until the session becomes
// active or is rejected. It times out after 5 minutes (60 attempts).
func (c *Client) pollApproval(sessionID string) error {
	const (
		pollInterval = 5 * time.Second
		maxAttempts  = 60 // 60 * 5s = 5 minutes
	)

	url := c.platformURL + "/api/v1/nhi-agent/connect/" + sessionID + "/status"

	for i := 0; i < maxAttempts; i++ {
		time.Sleep(pollInterval)

		resp, err := c.httpClient.Get(url)
		if err != nil {
			// Transient network error; continue polling.
			continue
		}

		var result struct {
			Status string `json:"status"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&result)
		resp.Body.Close()

		switch result.Status {
		case "active":
			return nil
		case "rejected":
			return fmt.Errorf("connect request rejected by admin")
		}
		// Any other status (still pending_approval, empty, etc.): keep waiting.
	}

	return fmt.Errorf("approval timeout (5 minutes)")
}

// nhiHeartbeat renews the current NHI session. Attestation is re-collected on
// each call so the platform can verify the environment has not changed since
// connect. On a 401 or 403 it triggers a full reconnect.
func (c *Client) nhiHeartbeat() error {
	attestType, evidence, err := c.collectAttestation()
	if err != nil {
		return fmt.Errorf("transit: collect attestation for heartbeat: %w", err)
	}

	// evidence must not be logged -- it may contain a Kubernetes SA token.
	body, _ := json.Marshal(map[string]interface{}{
		"nhi_id": c.nhiID,
		"attestation": map[string]string{
			"type":     attestType,
			"evidence": evidence,
		},
	})

	c.sessionMu.Lock()
	sid := c.sessionID
	c.sessionMu.Unlock()

	req, err := http.NewRequest(http.MethodPost, c.platformURL+"/api/v1/nhi-agent/heartbeat", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("transit: build heartbeat request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-NHI-Session", sid)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("transit: heartbeat request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		// Session has been revoked or expired server-side; reconnect.
		return c.nhiConnect()
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("transit: heartbeat failed: HTTP %d", resp.StatusCode)
	}
	return nil
}

// nhiRefreshLoop sends a heartbeat every 50 minutes until stopCh is closed.
func (c *Client) nhiRefreshLoop() {
	const interval = 50 * time.Minute
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-c.stopCh:
			return
		case <-ticker.C:
			// Errors are transient; the next tick will retry.
			_ = c.nhiHeartbeat()
		}
	}
}

// nhiDisconnect sends a best-effort DELETE/POST to invalidate the session
// server-side. Errors are intentionally ignored because Close must not block.
func (c *Client) nhiDisconnect() {
	c.sessionMu.Lock()
	sid := c.sessionID
	c.sessionMu.Unlock()

	body, _ := json.Marshal(map[string]string{"nhi_id": c.nhiID})
	req, err := http.NewRequest(http.MethodPost, c.platformURL+"/api/v1/nhi-agent/disconnect", bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-NHI-Session", sid)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return
	}
	resp.Body.Close()
}

// ---------------------------------------------------------- authedGet

// authedGet performs an authenticated GET request using the NHI session.
// On 401 the session is renewed via nhiConnect and the request is retried once.
func (c *Client) authedGet(url string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	c.sessionMu.Lock()
	req.Header.Set("X-NHI-Session", c.sessionID)
	c.sessionMu.Unlock()

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 401 {
		return resp, nil
	}
	resp.Body.Close()

	// Session expired: reconnect and retry once.
	if err := c.nhiConnect(); err != nil {
		return nil, fmt.Errorf("transit: session expired and reconnect failed: %w", err)
	}
	req2, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	c.sessionMu.Lock()
	req2.Header.Set("X-NHI-Session", c.sessionID)
	c.sessionMu.Unlock()
	return c.httpClient.Do(req2)
}
