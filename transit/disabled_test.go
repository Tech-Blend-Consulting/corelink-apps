package transit

import (
	"errors"
	"net/http/httptest"
	"testing"
)

// A secret disabled in CoreLink is withdrawn from an application that already
// has it: OnUnavailable fires once, and when it is enabled again the secret's
// callback fires with its value, as on the first fetch, so the application
// picks it back up. CoreLink refusing the key and the connector refusing the
// envelope are both reported as ErrSecretWithheld.
func TestADisabledSecretIsWithdrawnAndReturned(t *testing.T) {
	for _, from := range []string{"corelink", "connector"} {
		t.Run(from, func(t *testing.T) {
			dek := newDEK(t)
			const id, name = "secret-one", "orders-app-db"
			conn := &fakeConnector{envelopes: map[string]sealedEnvelope{
				name: {SecretID: id, Name: name, Version: 1, Envelope: seal(t, "pw-1", id, 1, dek)},
			}}
			plat := &fakePlatform{keys: map[string][]byte{id: dek}, versions: map[string]int{id: 1}}
			connSrv := httptest.NewServer(conn.handler())
			defer connSrv.Close()
			platSrv := httptest.NewServer(plat.handler())
			defer platSrv.Close()

			w := NewWatcher(clientFor(t, connSrv.URL, platSrv.URL), 0)
			var values []string
			var withdrawn []error
			w.WatchSecret(name, func(v string) { values = append(values, v) })
			w.OnUnavailable(func(n string, err error) {
				if n != name {
					t.Errorf("withdrawn %q, want %q", n, name)
				}
				withdrawn = append(withdrawn, err)
			})

			w.poll()
			if len(values) != 1 || values[0] != "pw-1" {
				t.Fatalf("first fetch: %v", values)
			}

			if from == "corelink" {
				plat.disabled = true // the connector still holds the envelope
			} else {
				conn.disabled = true
			}
			w.poll()
			w.poll()
			if len(withdrawn) != 1 || !errors.Is(withdrawn[0], ErrSecretWithheld) {
				t.Fatalf("withdrawn: %v", withdrawn)
			}

			plat.disabled, conn.disabled = false, false
			w.poll()
			if len(values) != 2 || values[1] != "pw-1" {
				t.Errorf("not delivered again once enabled: %v", values)
			}
			if len(withdrawn) != 1 {
				t.Errorf("withdrawn again after it came back: %v", withdrawn)
			}
		})
	}
}

// A secret that was never delivered is not reported as withdrawn: there is
// nothing for the application to drop.
func TestDisabledBeforeTheFirstFetchIsNotAWithdrawal(t *testing.T) {
	conn := &fakeConnector{disabled: true}
	plat := &fakePlatform{}
	connSrv := httptest.NewServer(conn.handler())
	defer connSrv.Close()
	platSrv := httptest.NewServer(plat.handler())
	defer platSrv.Close()

	c := clientFor(t, connSrv.URL, platSrv.URL)
	if _, err := c.GetSecretSealed("orders-app-db"); !errors.Is(err, ErrSecretWithheld) {
		t.Fatalf("GetSecretSealed: %v", err)
	}
	w := NewWatcher(c, 0)
	w.WatchSecret("orders-app-db", func(string) { t.Error("delivered while disabled") })
	w.OnUnavailable(func(string, error) { t.Error("withdrawn before it was ever delivered") })
	w.poll()
}

// CoreLink refusing the key because the secret's database connection is
// locked is a withdrawal too.
func TestALockedConnectionIsAWithdrawal(t *testing.T) {
	dek := newDEK(t)
	const id, name = "secret-one", "orders-app-db"
	conn := &fakeConnector{envelopes: map[string]sealedEnvelope{
		name: {SecretID: id, Name: name, Version: 1, Envelope: seal(t, "pw-1", id, 1, dek)},
	}}
	plat := &fakePlatform{keys: map[string][]byte{id: dek}, versions: map[string]int{id: 1}, lockCode: "DB_CONNECTION_LOCKED"}
	connSrv := httptest.NewServer(conn.handler())
	defer connSrv.Close()
	platSrv := httptest.NewServer(plat.handler())
	defer platSrv.Close()

	c := clientFor(t, connSrv.URL, platSrv.URL)
	if _, err := c.GetSecretSealed(name); err != nil {
		t.Fatal(err)
	}
	plat.disabled = true
	if _, err := c.GetSecretSealed(name); !errors.Is(err, ErrSecretWithheld) {
		t.Errorf("locked connection: %v", err)
	}
}

// Suspending the application's identity deletes its session and refuses it a
// new one. The SDK reconnects on the 401, is refused, and the Watcher
// withdraws every secret it delivered at once. Resumed, it connects again and
// the secrets are delivered again.
func TestASuspendedIdentityWithdrawsEverything(t *testing.T) {
	dek := newDEK(t)
	conn := &fakeConnector{envelopes: map[string]sealedEnvelope{
		"orders-app-db": {SecretID: "s1", Name: "orders-app-db", Version: 1, Envelope: seal(t, "pw-1", "s1", 1, dek)},
		"payments-key":  {SecretID: "s2", Name: "payments-key", Version: 1, Envelope: seal(t, "key-1", "s2", 1, dek)},
	}}
	plat := &fakePlatform{keys: map[string][]byte{"s1": dek, "s2": dek}, versions: map[string]int{"s1": 1, "s2": 1}}
	connSrv := httptest.NewServer(conn.handler())
	defer connSrv.Close()
	platSrv := httptest.NewServer(plat.handler())
	defer platSrv.Close()

	c := clientFor(t, connSrv.URL, platSrv.URL)
	w := NewWatcher(c, 0)
	delivered := map[string]int{}
	var withdrawn []string
	for _, n := range []string{"orders-app-db", "payments-key"} {
		n := n
		w.WatchSecret(n, func(string) { delivered[n]++ })
	}
	w.OnUnavailable(func(name string, err error) {
		if !errors.Is(err, ErrIdentityRefused) || !errors.Is(err, ErrSecretWithheld) {
			t.Errorf("withdrawn with %v", err)
		}
		withdrawn = append(withdrawn, name)
	})

	w.poll()
	if delivered["orders-app-db"] != 1 || delivered["payments-key"] != 1 {
		t.Fatalf("first fetch: %v", delivered)
	}

	plat.suspended = true
	w.poll()
	if len(withdrawn) != 2 {
		t.Fatalf("withdrawn %v, want both secrets", withdrawn)
	}
	connectsWhileSuspended := plat.connects
	w.poll()
	if len(withdrawn) != 2 {
		t.Errorf("withdrawn again: %v", withdrawn)
	}
	if plat.connects-connectsWhileSuspended > 1 {
		t.Errorf("%d connects in one poll while refused, want at most 1", plat.connects-connectsWhileSuspended)
	}

	// Resumed. Within refusedRetry it is not asked again; after it, it is,
	// and the secrets come back on a new session.
	plat.suspended = false
	before := plat.connects
	w.poll()
	if plat.connects != before || delivered["orders-app-db"] != 1 {
		t.Errorf("asked again within %s: connects %d -> %d, delivered %v", refusedRetry, before, plat.connects, delivered)
	}
	c.sessionMu.Lock()
	c.refusedAt = c.refusedAt.Add(-refusedRetry)
	c.sessionMu.Unlock()
	w.poll()
	if delivered["orders-app-db"] != 2 || delivered["payments-key"] != 2 {
		t.Errorf("not delivered again once resumed: %v", delivered)
	}
}
