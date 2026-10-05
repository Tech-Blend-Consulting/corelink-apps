package transit

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeBroker stands in for CoreLink's credential endpoints.
type fakeBroker struct {
	mu sync.Mutex
	// renewals counts successful renewals, and renewLimit is where it starts
	// refusing -- which is what CoreLink does past a maximum lifetime or count.
	renewals   int
	renewLimit int
	// renewStatus overrides the status returned, for the cases that are not
	// about counting.
	renewStatus int
	released    []string
	requested   []map[string]interface{}
	ttl         time.Duration
}

func (f *fakeBroker) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()

		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/nhi-agent/credentials":
			var body map[string]interface{}
			_ = json.NewDecoder(r.Body).Decode(&body)
			f.requested = append(f.requested, body)
			ttl := f.ttl
			if ttl == 0 {
				ttl = time.Hour
			}
			now := time.Now()
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"lease_id": "lease-1",
				// A string, which is what CoreLink sends.
				"credential": `{"username":"dyn_abc","password":"p"}`,
				"issued_at":  now,
				"expires_at": now.Add(ttl),
			})

		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/renew"):
			if f.renewStatus != 0 {
				w.WriteHeader(f.renewStatus)
				return
			}
			if f.renewLimit > 0 && f.renewals >= f.renewLimit {
				// What CoreLink says when a lease will not extend again.
				w.WriteHeader(http.StatusUnprocessableEntity)
				return
			}
			f.renewals++
			_ = json.NewEncoder(w).Encode(map[string]bool{"renewed": true})

		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/api/v1/nhi-agent/credentials/"):
			parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
			f.released = append(f.released, parts[len(parts)-1])
			w.WriteHeader(http.StatusNoContent)

		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/nhi-agent/credentials":
			now := time.Now()
			// "data" is the key CoreLink sends. The fake said "leases" until a
			// live call proved otherwise, which is the whole argument for not
			// trusting a fake written from the handler's own variable names.
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": []map[string]interface{}{
					{"id": "lease-1", "issued_at": now, "expires_at": now.Add(time.Hour)},
				},
			})

		default:
			http.NotFound(w, r)
		}
	})
}

func (f *fakeBroker) renewCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.renewals
}

// newBrokerClient wires a client to a running fake broker.
func newBrokerClient(t *testing.T, broker *fakeBroker) (*Client, func()) {
	t.Helper()
	srv := httptest.NewServer(broker.handler())
	c := New(Options{
		PlatformURL: srv.URL,
		NHIID:       "11111111-1111-1111-1111-111111111111",
	})
	c.sessionID = "session-in-place"
	return c, srv.Close
}

func TestRequestCredentialReturnsALeaseWithItsTerms(t *testing.T) {
	broker := &fakeBroker{ttl: 30 * time.Minute}
	c, closeSrv := newBrokerClient(t, broker)
	defer closeSrv()

	lease, err := c.RequestCredential(ResourceDatabase, "db-conn-1", 15*time.Minute)
	if err != nil {
		t.Fatalf("RequestCredential: %v", err)
	}

	t.Run("the lease carries what renewal needs", func(t *testing.T) {
		if lease.ID == "" {
			t.Error("no lease id, so the credential could never be renewed or released")
		}
		if lease.ExpiresAt.IsZero() {
			t.Error("no expiry, so nothing can tell when to renew")
		}
		if !strings.Contains(lease.Credential, "dyn_abc") {
			t.Errorf("credential does not carry the issued username")
		}
		if remaining := lease.Remaining(); remaining <= 0 || remaining > 30*time.Minute {
			t.Errorf("Remaining() = %s, want within the granted term", remaining)
		}
	})

	t.Run("the requested TTL is sent, and the granted one is what comes back", func(t *testing.T) {
		// Asking is not deciding: CoreLink grants what policy allows, and the
		// lease says what was actually granted.
		if got := broker.requested[0]["ttl_seconds"]; got != float64(900) {
			t.Errorf("ttl_seconds sent = %v, want 900", got)
		}
		if lease.ExpiresAt.Sub(lease.IssuedAt) != 30*time.Minute {
			t.Errorf("granted term = %s, want the broker's 30m rather than the 15m asked for",
				lease.ExpiresAt.Sub(lease.IssuedAt))
		}
	})

	t.Run("the credential is redacted from the lease's own rendering", func(t *testing.T) {
		// A lease gets logged while tracing its lifecycle far more often than a
		// secret does, so its default rendering must not be the leak.
		if s := lease.String(); strings.Contains(s, "dyn_abc") || strings.Contains(s, "password") {
			t.Errorf("String() = %q, which carries the credential", s)
		}
	})
}

func TestRequestCredentialRefusesWhatCoreLinkWouldReject(t *testing.T) {
	broker := &fakeBroker{}
	c, closeSrv := newBrokerClient(t, broker)
	defer closeSrv()

	// Refused here rather than round-tripped, because the allowlist is fixed and
	// a typo should not look like a permission problem.
	if _, err := c.RequestCredential("kubernetes", "x", 0); err == nil {
		t.Error("an unknown resource type was sent to CoreLink")
	}
	if _, err := c.RequestCredential(ResourceDatabase, "", 0); err == nil {
		t.Error("an empty resource id was sent to CoreLink")
	}
	if len(broker.requested) != 0 {
		t.Errorf("%d requests reached CoreLink, want none", len(broker.requested))
	}
}

func TestRenewLeaseTellsExhaustedApartFromFailed(t *testing.T) {
	cases := []struct {
		name   string
		status int
		want   error
	}{
		// The one that matters: the credential has reached its limit, so
		// retrying is pointless and the application must request a new one.
		{"exhausted", http.StatusUnprocessableEntity, ErrLeaseExhausted},
		{"not found", http.StatusNotFound, ErrLeaseNotFound},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			broker := &fakeBroker{renewStatus: tc.status}
			c, closeSrv := newBrokerClient(t, broker)
			defer closeSrv()

			if err := c.RenewLease("lease-1"); !errors.Is(err, tc.want) {
				t.Errorf("RenewLease returned %v, want %v", err, tc.want)
			}
		})
	}

	t.Run("a renewal that works reports nothing", func(t *testing.T) {
		broker := &fakeBroker{}
		c, closeSrv := newBrokerClient(t, broker)
		defer closeSrv()

		if err := c.RenewLease("lease-1"); err != nil {
			t.Errorf("RenewLease: %v", err)
		}
		if broker.renewCount() != 1 {
			t.Errorf("renewals = %d, want 1", broker.renewCount())
		}
	})

	t.Run("a session is required", func(t *testing.T) {
		broker := &fakeBroker{}
		c, closeSrv := newBrokerClient(t, broker)
		defer closeSrv()
		c.sessionID = ""

		if err := c.RenewLease("lease-1"); err == nil {
			t.Error("a renewal was attempted with no session")
		}
	})
}

func TestReleaseCredentialIsIdempotent(t *testing.T) {
	broker := &fakeBroker{}
	c, closeSrv := newBrokerClient(t, broker)
	defer closeSrv()

	if err := c.ReleaseCredential("lease-1"); err != nil {
		t.Fatalf("ReleaseCredential: %v", err)
	}
	if len(broker.released) != 1 || broker.released[0] != "lease-1" {
		t.Errorf("released = %v, want lease-1", broker.released)
	}

	t.Run("a lease already gone is not an error", func(t *testing.T) {
		// The caller's intent is satisfied either way, and a process cleaning up
		// after a restart should not have to tell the two apart.
		gone := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.NotFound(w, r)
		}))
		defer gone.Close()

		c2 := New(Options{PlatformURL: gone.URL, NHIID: "x"})
		c2.sessionID = "session-in-place"
		if err := c2.ReleaseCredential("lease-1"); err != nil {
			t.Errorf("releasing a gone lease returned %v, want nil", err)
		}
	})
}

func TestListLeasesReportsWhatIsHeldWithoutTheCredential(t *testing.T) {
	broker := &fakeBroker{}
	c, closeSrv := newBrokerClient(t, broker)
	defer closeSrv()

	leases, err := c.ListLeases()
	if err != nil {
		t.Fatalf("ListLeases: %v", err)
	}
	if len(leases) != 1 || leases[0].ID != "lease-1" {
		t.Fatalf("got %v, want one lease named lease-1", leases)
	}
	// The material is handed over once, at issue. A listing that returned it
	// would make every lease re-readable for its whole life.
	if leases[0].Credential != "" {
		t.Error("the listing carried a credential")
	}
	if leases[0].ExpiresAt.IsZero() {
		t.Error("the listing carried no expiry, so a caller cannot tell what is nearly up")
	}
}

// KeepAlive renews while the credential is in use, and stops when CoreLink says
// it will not extend again -- which is what makes running it in the background
// safe rather than a way to hold a short-lived credential forever.
func TestKeepAliveRenewsAndStopsWhenRefused(t *testing.T) {
	t.Run("it renews while the lease lives", func(t *testing.T) {
		broker := &fakeBroker{}
		c, closeSrv := newBrokerClient(t, broker)
		defer closeSrv()
		c.renewFloor = 10 * time.Millisecond

		lease := Lease{ID: "lease-1", IssuedAt: time.Now(), ExpiresAt: time.Now().Add(40 * time.Millisecond)}
		stop := c.KeepAlive(lease, nil)
		defer stop()

		deadline := time.Now().Add(2 * time.Second)
		for broker.renewCount() < 2 && time.Now().Before(deadline) {
			time.Sleep(5 * time.Millisecond)
		}
		if broker.renewCount() < 2 {
			t.Errorf("renewals = %d, want it renewing repeatedly", broker.renewCount())
		}
	})

	t.Run("it stops when the lease is exhausted and says so once", func(t *testing.T) {
		broker := &fakeBroker{renewLimit: 1}
		c, closeSrv := newBrokerClient(t, broker)
		defer closeSrv()
		c.renewFloor = 10 * time.Millisecond

		var mu sync.Mutex
		var reported []error
		lease := Lease{ID: "lease-1", IssuedAt: time.Now(), ExpiresAt: time.Now().Add(40 * time.Millisecond)}
		stop := c.KeepAlive(lease, func(err error) {
			mu.Lock()
			reported = append(reported, err)
			mu.Unlock()
		})
		defer stop()

		deadline := time.Now().Add(2 * time.Second)
		for {
			mu.Lock()
			n := len(reported)
			mu.Unlock()
			if n > 0 || time.Now().After(deadline) {
				break
			}
			time.Sleep(5 * time.Millisecond)
		}

		mu.Lock()
		defer mu.Unlock()
		if len(reported) != 1 {
			t.Fatalf("onExpiry called %d times, want exactly once", len(reported))
		}
		if !errors.Is(reported[0], ErrLeaseExhausted) {
			t.Errorf("reported %v, want ErrLeaseExhausted so the application knows to re-request", reported[0])
		}

		// And it must have stopped: no further renewals after the refusal.
		before := broker.renewCount()
		time.Sleep(60 * time.Millisecond)
		if broker.renewCount() != before {
			t.Errorf("renewals went from %d to %d after a refusal; it did not stop",
				before, broker.renewCount())
		}
	})

	t.Run("stop ends it and can be called twice", func(t *testing.T) {
		broker := &fakeBroker{}
		c, closeSrv := newBrokerClient(t, broker)
		defer closeSrv()
		c.renewFloor = 10 * time.Millisecond

		lease := Lease{ID: "lease-1", IssuedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)}
		stop := c.KeepAlive(lease, nil)
		stop()
		stop() // a double stop must not panic on a closed channel

		before := broker.renewCount()
		time.Sleep(40 * time.Millisecond)
		if broker.renewCount() != before {
			t.Errorf("renewals continued after stop: %d -> %d", before, broker.renewCount())
		}
	})
}
