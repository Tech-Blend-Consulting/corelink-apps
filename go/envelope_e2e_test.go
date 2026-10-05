//go:build e2e

// Proves envelope mode as an application actually uses it: the published SDK,
// attesting with its own identity, taking ciphertext from a running connector
// and the key from a running CoreLink, and opening the secret itself.
//
// The unit tests beside this one use fakes, which cannot show that the two wire
// formats agree -- the envelope CoreLink writes and the one this reads, and the
// additional authenticated data both sides construct independently. That is
// exactly the kind of agreement a fake assumes.
//
// Needs a live environment:
//
//	docker compose up -d
//	docker compose exec -T postgres psql -U secrets -d secrets_mgmt < tests/e2e/delivery/fixtures.sql
//	tbcl-transit-agent --nhi-id 11111111-1111-1111-1111-111111111111 \
//	  --platform http://localhost:8080 --envelope-addr 127.0.0.1:9092
//	go test -tags e2e ./sdk/go/transit/ -run TestE2E -v
//
// The secrets and grants come from tests/e2e/delivery; see docs/secret-delivery.md.
package transit

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

const (
	e2eAppNHI    = "22222222-2222-2222-2222-222222222222"
	e2eSecret    = "e2e/dbone"
	e2eOtherName = "e2e/dbtwo"
)

func e2eEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func TestE2E_SDKOpensWhatTheConnectorHolds(t *testing.T) {
	platform := e2eEnv("TEST_BASE_URL", "http://localhost:8080")
	connector := e2eEnv("TEST_ENVELOPE_ADDR", "http://127.0.0.1:9092")

	c := New(Options{
		TransitURL:  connector,
		PlatformURL: platform,
		NHIID:       e2eAppNHI,
	})
	defer c.Close()

	// Approving alongside Bootstrap, which blocks while it polls. Host
	// attestation hashes the running binary, so a recompiled test binary is a new
	// workload and asks for approval every time -- see tests/e2e/delivery.
	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-done:
				return
			case <-time.After(2 * time.Second):
				e2eApprove(t)
			}
		}
	}()
	err := c.Bootstrap()
	close(done)
	if err != nil {
		t.Skipf("could not attest as the application identity: %v", err)
	}

	t.Run("the secret opens", func(t *testing.T) {
		// Through the connector and CoreLink, with no plaintext anywhere between
		// them: the connector holds secrets:cache and cannot open what it serves,
		// and this identity holds secrets:unwrap and cannot read plaintext.
		//
		// Waited for, because the connector cannot approve its own first connect
		// either, and until it is approved it has no session to fetch with. It
		// reports that as a plain not-found, the same answer a name outside its
		// grant gets -- deliberately, so a caller cannot tell them apart.
		got := e2eEventually(t, c, e2eSecret)
		if got != "the-one-true-password" {
			t.Errorf("got %q, want the stored value", got)
		}
	})

	t.Run("the two sides agree on the binding", func(t *testing.T) {
		// Implied by the subtest above, and worth stating: had this SDK's
		// secretAAD disagreed with the platform's crypto.SecretAAD by a single
		// byte, nothing would have opened. That agreement is the thing no fake
		// can check.
		if _, err := c.GetSecretSealed(e2eOtherName); err != nil {
			t.Errorf("GetSecretSealed(%q): %v", e2eOtherName, err)
		}
	})

	t.Run("GetSecret goes the sealed way too", func(t *testing.T) {
		// An application that already called GetSecret needs no change: with a
		// connector configured it now takes the envelope and the key rather than
		// asking for plaintext, which the connector no longer serves.
		got, err := c.GetSecret(e2eSecret)
		if err != nil {
			t.Fatalf("GetSecret(%q): %v", e2eSecret, err)
		}
		if got != "the-one-true-password" {
			t.Errorf("got %q, want the stored value", got)
		}
	})

	t.Run("the connector offers no listing", func(t *testing.T) {
		// By design: envelopes are served by name and there is no way to
		// enumerate them.
		if _, err := c.ListSecrets(); err == nil {
			t.Error("a connector returned a listing")
		}
	})

	t.Run("a certificate comes back as a bundle", func(t *testing.T) {
		// The whole path, over HTTP, for the shape that used to need the
		// connector to hold plaintext: envelope from the connector, key from
		// CoreLink, bundle parsed here.
		cert, err := c.GetCertificate("e2e/web-tls")
		if err != nil {
			t.Fatalf("GetCertificate: %v", err)
		}
		if !strings.Contains(cert.Certificate, "BEGIN CERTIFICATE") ||
			!strings.Contains(cert.PrivateKey, "BEGIN PRIVATE KEY") {
			t.Errorf("got %+v, want a certificate and a key", cert)
		}
	})

	t.Run("a password is not a certificate", func(t *testing.T) {
		if cert, err := c.GetCertificate(e2eSecret); err == nil {
			t.Errorf("a password came back as a certificate: %+v", cert)
		}
	})

	t.Run("a name outside the grant is refused", func(t *testing.T) {
		// Refused by the connector having no envelope for it, because the
		// platform will not let the connector cache outside its own grant.
		if got, err := c.GetSecretSealed("production/not-mine"); err == nil {
			t.Errorf("a name outside the grant returned %q", got)
		}
	})
}

// e2eApprove stands in for an administrator approving a first connect.
func e2eApprove(t *testing.T) {
	t.Helper()
	sql, err := os.ReadFile("../../../tests/e2e/delivery/approve.sql")
	if err != nil {
		return
	}
	cmd := exec.Command("docker", "compose", "exec", "-T", "postgres",
		"psql", "-U", "secrets", "-d", "secrets_mgmt", "-q")
	cmd.Dir = "../../.."
	cmd.Stdin = bytes.NewReader(sql)
	_ = cmd.Run()
}

// e2eEventually fetches a secret, approving and retrying while the connector
// gets its own first connect approved.
func e2eEventually(t *testing.T, c *Client, name string) string {
	t.Helper()
	deadline := time.Now().Add(45 * time.Second)
	for {
		got, err := c.GetSecretSealed(name)
		if err == nil {
			return got
		}
		if time.Now().After(deadline) {
			t.Fatalf("GetSecretSealed(%q) never succeeded: %v; "+
				"either the connector is not approved or the name is outside its cache grant", name, err)
		}
		e2eApprove(t)
		time.Sleep(2 * time.Second)
	}
}
