//go:build e2e

// The leased-credential lifecycle against a running CoreLink: request, renew,
// list, release, and the cap that stops a short-lived credential being kept
// alive forever.
//
// The unit tests beside this run against a fake written from the handler's own
// code, which is exactly how this SDK came to read the wrong key out of the
// lease listing -- the fake agreed with the mistake. Only a live call disagreed.
//
// Needs a live environment, and an identity holding secrets:read on the secret
// it leases against:
//
//	docker compose up -d
//	docker compose exec -T postgres psql -U secrets -d secrets_mgmt < tests/e2e/delivery/fixtures.sql
//	go test -tags e2e ./sdk/go/ -run TestE2E_Lease -v
//
// See docs/secret-delivery.md.
package transit

import (
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// e2eLeaserNHI holds secrets:read on e2e/*, created by fixtures.sql.
const e2eLeaserNHI = "44444444-4444-4444-4444-444444444444"

func TestE2E_LeaseLifecycle(t *testing.T) {
	platform := e2eEnv("TEST_BASE_URL", "http://localhost:8080")

	// The leaser, not the application: leasing is authorized by secrets:read,
	// and e2e-app deliberately holds only unwrap so the delivery test can prove
	// an unwrap-only identity is refused plaintext.
	c := New(Options{PlatformURL: platform, NHIID: e2eLeaserNHI})
	defer c.Close()

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

	// The secret to lease against, found by name through the identity's own
	// grants rather than hard-coded.
	metas, err := e2eListSecrets(t, c)
	if err != nil {
		t.Skipf("could not list this identity's secrets: %v", err)
	}
	secretID := metas["e2e/dbone"]
	if secretID == "" {
		t.Skip("e2e/dbone is not available to this identity; run fixtures.sql")
	}

	var lease Lease

	t.Run("a credential is leased with terms", func(t *testing.T) {
		lease, err = c.RequestCredential(ResourceSecret, secretID, 5*time.Minute)
		if err != nil {
			// Before the broker authorized on the resolved resource, this was
			// refused for every identity that was not tenant-wide wildcard.
			t.Fatalf("RequestCredential: %v", err)
		}
		if lease.ID == "" || lease.ExpiresAt.IsZero() {
			t.Fatalf("got %+v, want a lease id and an expiry", lease)
		}
		if lease.Credential == "" {
			t.Error("the lease carried no credential")
		}
	})

	t.Run("it renews", func(t *testing.T) {
		// This answered 404 for the life of the endpoint: renewal looked only in
		// the dynamic-credential table, and a lease from the credentials API is
		// not there.
		if err := c.RenewLease(lease.ID); err != nil {
			t.Fatalf("RenewLease: %v", err)
		}
	})

	t.Run("the listing names it without the credential", func(t *testing.T) {
		leases, err := c.ListLeases()
		if err != nil {
			t.Fatalf("ListLeases: %v", err)
		}
		var found bool
		for _, l := range leases {
			if l.ID == lease.ID {
				found = true
				if l.Credential != "" {
					t.Error("the listing carried the credential, making it re-readable for the lease's life")
				}
				if l.ExpiresAt.IsZero() {
					t.Error("the listing carried no expiry")
				}
			}
		}
		if !found {
			t.Errorf("the lease just issued is not in the listing of %d", len(leases))
		}
	})

	t.Run("renewal stops at the maximum lifetime", func(t *testing.T) {
		// The property that makes a background renewal loop safe: the bound is
		// CoreLink's, not the caller's. Aged in the database rather than waited
		// out, because the cap is an hour.
		if err := e2eAgeLease(t, lease.ID, "59 minutes"); err != nil {
			t.Skipf("could not age the lease: %v", err)
		}
		err := c.RenewLease(lease.ID)
		if !errors.Is(err, ErrLeaseExhausted) {
			t.Errorf("RenewLease at the cap returned %v, want ErrLeaseExhausted so the "+
				"application knows to request a new credential rather than retrying", err)
		}
	})

	t.Run("it releases, and releasing twice is not an error", func(t *testing.T) {
		if err := c.ReleaseCredential(lease.ID); err != nil {
			t.Fatalf("ReleaseCredential: %v", err)
		}
		if err := c.ReleaseCredential(lease.ID); err != nil {
			t.Errorf("releasing an already-released lease returned %v, want nil", err)
		}
	})

	t.Run("an unknown lease is not found rather than renewed", func(t *testing.T) {
		err := c.RenewLease("00000000-0000-0000-0000-000000000000")
		if !errors.Is(err, ErrLeaseNotFound) {
			t.Errorf("RenewLease on an unknown id returned %v, want ErrLeaseNotFound", err)
		}
	})
}

// e2eListSecrets maps this identity's secret names to ids.
//
// Uses the resolver rather than ListSecrets, which returns names alone: a lease
// is requested against an id, and the point of resolving is that an application
// configures names and never writes an id down.
func e2eListSecrets(t *testing.T, c *Client) (map[string]string, error) {
	t.Helper()
	index, err := c.resolveNames()
	if err != nil {
		return nil, err
	}
	out := make(map[string]string, len(index))
	for name, id := range index {
		out[name] = id
	}
	return out, nil
}

// e2eAgeLease moves a lease's issue time back, so the cap can be reached
// without waiting an hour for it.
func e2eAgeLease(t *testing.T, leaseID, interval string) error {
	t.Helper()
	cmd := exec.Command("docker", "compose", "exec", "-T", "postgres",
		"psql", "-U", "secrets", "-d", "secrets_mgmt", "-q", "-c",
		"update credential_leases set issued_at = now() - interval '"+interval+"' where id = '"+leaseID+"';")
	cmd.Dir = "../../.."
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if strings.Contains(leaseID, "'") {
		return errors.New("refusing a lease id with a quote in it")
	}
	return cmd.Run()
}
