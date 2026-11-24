package transit

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
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

// changingPlatform is a platform whose listing, list failures and per-id
// answers a test changes as it goes, counting the listings it serves.
type changingPlatform struct {
	mu        sync.Mutex
	failLists int               // listings still to answer with a 500
	listing   map[string]string // name -> id
	values    map[string]string // id -> value; an id absent is a 404
	lists     int
}

func (p *changingPlatform) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		defer p.mu.Unlock()
		if r.URL.Path == "/api/v1/nhi-agent/secrets" {
			p.lists++
			if p.failLists > 0 {
				p.failLists--
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			data := make([]map[string]string, 0, len(p.listing))
			for name, id := range p.listing {
				data = append(data, map[string]string{"id": id, "name": name})
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": data})
			return
		}
		id := strings.TrimPrefix(r.URL.Path, "/api/v1/nhi-agent/secrets/")
		v, ok := p.values[id]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{
			"secret_id": id,
			"value":     base64.StdEncoding.EncodeToString([]byte(v)),
		})
	})
}

func (p *changingPlatform) set(f func(p *changingPlatform)) {
	p.mu.Lock()
	defer p.mu.Unlock()
	f(p)
}

func (p *changingPlatform) listCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.lists
}

func directClientFor(t *testing.T, p *changingPlatform) *Client {
	t.Helper()
	srv := httptest.NewServer(p.handler())
	t.Cleanup(srv.Close)
	c := New(Options{PlatformURL: srv.URL, NHIID: "nhi-1"})
	c.sessionID = "session-1"
	return c
}

// The name index used to be filled under a sync.Once, so one failed listing
// was returned for the life of the process and a grant made after the first
// listing was never seen.
func TestDirectModeNameIndexRecovers(t *testing.T) {
	t.Run("a failed listing is not kept", func(t *testing.T) {
		p := &changingPlatform{
			failLists: 1,
			listing:   map[string]string{"production/dbone": "id-1"},
			values:    map[string]string{"id-1": "the-value"},
		}
		c := directClientFor(t, p)

		if _, err := c.GetSecret("production/dbone"); err == nil {
			t.Fatal("the first read succeeded although the listing failed")
		}
		got, err := c.GetSecret("production/dbone")
		if err != nil {
			t.Fatalf("the read after a failed listing did not recover: %v", err)
		}
		if got != "the-value" {
			t.Errorf("got %q, want the stored value", got)
		}
	})

	t.Run("a failed refresh is reported, not answered as not available", func(t *testing.T) {
		p := &changingPlatform{listing: map[string]string{}, values: map[string]string{}}
		c := directClientFor(t, p)
		c.names.floor = time.Nanosecond
		if _, err := c.ListSecrets(); err != nil {
			t.Fatalf("list: %v", err)
		}
		p.set(func(p *changingPlatform) { p.failLists = 1 })
		time.Sleep(time.Millisecond)
		_, err := c.GetSecret("production/new")
		if err == nil || !strings.Contains(err.Error(), "HTTP 500") {
			t.Errorf("a failed refresh read as %v, want the listing's failure", err)
		}
	})

	t.Run("a name granted after the first listing is found", func(t *testing.T) {
		p := &changingPlatform{
			listing: map[string]string{"production/dbone": "id-1"},
			values:  map[string]string{"id-1": "one", "id-2": "two"},
		}
		c := directClientFor(t, p)
		c.names.floor = time.Nanosecond

		if _, err := c.GetSecret("production/dbone"); err != nil {
			t.Fatalf("get: %v", err)
		}
		p.set(func(p *changingPlatform) { p.listing["production/dbtwo"] = "id-2" })
		time.Sleep(time.Millisecond)

		got, err := c.GetSecret("production/dbtwo")
		if err != nil {
			t.Fatalf("a newly granted name was not found: %v", err)
		}
		if got != "two" {
			t.Errorf("got %q, want %q", got, "two")
		}
	})

	t.Run("resolve sees a name granted after the first listing", func(t *testing.T) {
		p := &changingPlatform{
			listing: map[string]string{"production/dbone": "id-1"},
			values:  map[string]string{},
		}
		c := directClientFor(t, p)
		c.names.floor = time.Nanosecond

		if err := c.Resolve("production/dbone"); err != nil {
			t.Fatalf("resolve: %v", err)
		}
		p.set(func(p *changingPlatform) { p.listing["production/dbtwo"] = "id-2" })
		time.Sleep(time.Millisecond)
		if err := c.Resolve("production/dbone", "production/dbtwo"); err != nil {
			t.Errorf("a newly granted name failed resolve: %v", err)
		}
	})

	t.Run("a secret recreated under a new id is read by the new id", func(t *testing.T) {
		p := &changingPlatform{
			listing: map[string]string{"production/dbone": "id-old"},
			values:  map[string]string{"id-old": "old"},
		}
		c := directClientFor(t, p)
		c.names.floor = time.Nanosecond

		if _, err := c.GetSecret("production/dbone"); err != nil {
			t.Fatalf("get: %v", err)
		}
		p.set(func(p *changingPlatform) {
			p.listing["production/dbone"] = "id-new"
			p.values = map[string]string{"id-new": "new"}
		})
		time.Sleep(time.Millisecond)

		got, err := c.GetSecret("production/dbone")
		if err != nil {
			t.Fatalf("a recreated secret was not read: %v", err)
		}
		if got != "new" {
			t.Errorf("got %q, want %q", got, "new")
		}
	})

	t.Run("a secret deleted since the listing is not available", func(t *testing.T) {
		p := &changingPlatform{
			listing: map[string]string{"production/dbone": "id-1"},
			values:  map[string]string{"id-1": "one"},
		}
		c := directClientFor(t, p)
		c.names.floor = time.Nanosecond

		if _, err := c.GetSecret("production/dbone"); err != nil {
			t.Fatalf("get: %v", err)
		}
		p.set(func(p *changingPlatform) {
			p.listing = map[string]string{}
			p.values = map[string]string{}
		})
		time.Sleep(time.Millisecond)

		_, err := c.GetSecret("production/dbone")
		if err == nil || !strings.Contains(err.Error(), "no secret") {
			t.Errorf("a deleted secret read as %v, want not available", err)
		}
	})

	t.Run("a 404 on an id the listing still names is reported", func(t *testing.T) {
		p := &changingPlatform{
			listing: map[string]string{"production/dbone": "id-1"},
			values:  map[string]string{},
		}
		c := directClientFor(t, p)
		c.names.floor = time.Nanosecond

		_, err := c.GetSecret("production/dbone")
		if err == nil || !strings.Contains(err.Error(), "HTTP 404") {
			t.Errorf("got %v, want the 404", err)
		}
	})

	t.Run("repeated misses do not list on every lookup", func(t *testing.T) {
		p := &changingPlatform{
			listing: map[string]string{"production/dbone": "id-1"},
			values:  map[string]string{"id-1": "one"},
		}
		c := directClientFor(t, p) // the default floor, seconds long

		for i := 0; i < 10; i++ {
			if _, err := c.GetSecret("production/not-granted"); err == nil {
				t.Fatal("an ungranted name was read")
			}
		}
		if n := p.listCount(); n != 1 {
			t.Errorf("%d listings for 10 misses, want 1", n)
		}
	})
}
