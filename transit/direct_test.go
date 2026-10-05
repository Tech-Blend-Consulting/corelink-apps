package transit

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Talking to the platform with nothing in between.
//
// The arrangement an application uses unless something forces otherwise: no
// agent to deploy, nothing beside it holding its secrets, and the value going
// from the platform into the process that asked for it.
func TestDirectModeReadsFromThePlatform(t *testing.T) {
	const wanted = "the-database-password"

	platform := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-NHI-Session") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch {
		case r.URL.Path == "/api/v1/nhi-agent/secrets":
			// Already narrowed by the identity's grants.
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": []map[string]string{
					{"id": "aaaaaaaa-0000-0000-0000-000000000001", "name": "production/dbone"},
					{"id": "aaaaaaaa-0000-0000-0000-000000000002", "name": "production/other"},
				},
			})
		case strings.HasSuffix(r.URL.Path, "/secrets/aaaaaaaa-0000-0000-0000-000000000001"):
			_ = json.NewEncoder(w).Encode(map[string]string{
				"secret_id": "aaaaaaaa-0000-0000-0000-000000000001",
				"value":     base64.StdEncoding.EncodeToString([]byte(wanted)),
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer platform.Close()

	c := New(Options{PlatformURL: platform.URL, NHIID: "nhi-1"})
	c.sessionID = "session-1" // stand in for attestation, exercised elsewhere

	t.Run("it is in direct mode with no agent configured", func(t *testing.T) {
		if !c.directMode() {
			t.Fatal("a client with no TransitURL should talk to the platform")
		}
	})

	t.Run("a configured name resolves and reads", func(t *testing.T) {
		got, err := c.GetSecret("production/dbone")
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		if got != wanted {
			t.Errorf("got %q, want %q -- the platform encodes the value, the caller wants what was stored", got, wanted)
		}
	})

	t.Run("a name the identity cannot have is refused by name alone", func(t *testing.T) {
		_, err := c.GetSecret("production/not-granted")
		if err == nil {
			t.Fatal("a secret outside the listing was returned")
		}
		// The listing is already narrowed by grants, so absent and forbidden are
		// the same answer. Saying which would report whether a secret exists.
		if strings.Contains(err.Error(), "403") || strings.Contains(err.Error(), "forbidden") {
			t.Errorf("the refusal distinguishes absent from forbidden: %v", err)
		}
	})

	t.Run("resolve reports every missing name at once", func(t *testing.T) {
		err := c.Resolve("production/dbone", "production/missing-a", "production/missing-b")
		if err == nil {
			t.Fatal("missing names were accepted at startup")
		}
		for _, want := range []string{"missing-a", "missing-b"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("%s not reported; an operator would fix one grant and redeploy to find the next", want)
			}
		}
		if strings.Contains(err.Error(), "dbone") {
			t.Error("a name that resolved was reported as missing")
		}
	})

	t.Run("resolve passes when everything is available", func(t *testing.T) {
		if err := c.Resolve("production/dbone", "production/other"); err != nil {
			t.Errorf("startup check failed on names that exist: %v", err)
		}
	})
}
