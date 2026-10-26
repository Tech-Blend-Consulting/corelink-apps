package transit

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// WithheldReason names why a secret is withheld, whichever side said so.
func TestWithheldReason(t *testing.T) {
	for _, tc := range []struct {
		status       int
		body         string
		fromCoreLink bool
		want         string
	}{
		{409, `{"error":{"code":"SECRET_DISABLED"}}`, true, ReasonSecretDisabled},
		{409, `{"error":{"code":"DB_CONNECTION_LOCKED"}}`, true, ReasonConnectionLocked},
		{409, `{"error":{"code":"DB_CONNECTION_LOCKED"}}`, false, ReasonConnectionLocked},
		{409, `{"error":{"code":"CONNECTOR_IDENTITY_REFUSED"}}`, false, ReasonConnectorRefused},
		{409, `the secret is disabled`, false, ReasonWithheld}, // an older connector
		{409, `{"error":{"code":"SOMETHING_ELSE"}}`, true, ""},
		{404, `no envelope for that name`, false, ""},
	} {
		got := withheldReasonOf(tc.status, []byte(tc.body), tc.fromCoreLink)
		if got != tc.want {
			t.Errorf("%d %s (corelink %v): %q, want %q", tc.status, tc.body, tc.fromCoreLink, got, tc.want)
		}
		if got == "" {
			continue
		}
		err := &withheldError{reason: got}
		if !errors.Is(err, ErrSecretWithheld) || WithheldReason(err) != got {
			t.Errorf("%q: Is %v, reason %q", got, errors.Is(err, ErrSecretWithheld), WithheldReason(err))
		}
	}
	if WithheldReason(ErrIdentityRefused) != ReasonIdentityRefused || WithheldReason(errors.New("x")) != "" {
		t.Error("identity refused or unrelated error misread")
	}
}

// WhoAmI asks CoreLink which identity the client is.
func TestWhoAmI(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/nhi-agent/whoami" || r.Header.Get("X-NHI-Session") == "" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{"nhi_id":"11111111-1111-1111-1111-111111111111","name":"customer-app","type":"service_account","status":"active"}`))
	}))
	defer srv.Close()
	c := clientFor(t, "", srv.URL)
	id, err := c.WhoAmI()
	if err != nil || id.Name != "customer-app" || id.Status != "active" || id.Type != "service_account" {
		t.Errorf("%+v %v", id, err)
	}
}

// OnError hears every failed fetch, including one never delivered.
func TestOnErrorHearsEveryFailure(t *testing.T) {
	conn := &fakeConnector{disabled: true}
	plat := &fakePlatform{}
	connSrv := httptest.NewServer(conn.handler())
	defer connSrv.Close()
	platSrv := httptest.NewServer(plat.handler())
	defer platSrv.Close()
	w := NewWatcher(clientFor(t, connSrv.URL, platSrv.URL), 0)
	w.WatchSecret("orders-app-db", func(string) {})
	var reasons []string
	w.OnError(func(name string, err error) { reasons = append(reasons, WithheldReason(err)) })
	w.poll()
	w.poll()
	if len(reasons) != 2 || reasons[0] != ReasonWithheld {
		t.Errorf("reasons %v", reasons)
	}
}
