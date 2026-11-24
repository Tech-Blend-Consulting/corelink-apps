package transit

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Direct mode: the application talks to CoreLink, with nothing in between.
//
// This is the ordinary arrangement. There is no agent to deploy, nothing beside
// the application holding its secrets, and the value goes from the platform into
// the process that asked for it and nowhere else. A client built without a
// TransitURL is in direct mode.
//
// An agent earns its place where the application has no route out, or where one
// host runs enough processes that sharing a session is worth a component. Those
// are deployment choices; nothing about how a secret is authorized changes.

// directMode reports whether this client talks to the platform itself.
func (c *Client) directMode() bool { return c.url == "" }

// nameIndex maps secret names to the ids the platform knows them by.
//
// Listed on first use and kept, because the names an application asks for are
// fixed by its configuration and everything after that is addressed by id. Only
// a listing that succeeded is kept: a failed one (a network blip, a 5xx) is
// returned to the caller and the next call lists again, so one bad moment at
// startup does not leave the client unable to read anything until it restarts.
//
// The index is refreshed when a name is missing from it or its id no longer
// exists, since a grant added, a secret created or a secret recreated under a
// new id all happen after the first listing. Those refreshes are at most one
// per refreshFloor, so an application repeatedly asking for a name it was never
// granted does not list the platform on every call.
type nameIndex struct {
	mu       sync.Mutex
	byName   map[string]string
	listedAt time.Time
	// floor overrides defaultNameRefreshFloor. Zero means the default; only
	// tests set it.
	floor time.Duration
}

// defaultNameRefreshFloor is the least time between two listings made to look
// for a name the index does not have.
const defaultNameRefreshFloor = 5 * time.Second

func (n *nameIndex) refreshFloor() time.Duration {
	if n.floor > 0 {
		return n.floor
	}
	return defaultNameRefreshFloor
}

// resolveNames returns the index, listing the secrets this identity may see
// when no listing has succeeded yet.
//
// What comes back is already narrowed by the identity's grants, so this says
// which of the configured names actually exist and are permitted -- which is why
// an application should resolve the whole of its configuration at startup rather
// than on first use. A name missing here is a deployment that will not work,
// and it is cheaper to learn that when it is deployed.
func (c *Client) resolveNames() (map[string]string, error) {
	return c.lookupNames(false)
}

// refreshNames lists again, unless the last listing is younger than the
// refresh floor, and returns the index. Used when a name is not in the index
// or its id is gone.
func (c *Client) refreshNames() (map[string]string, error) {
	return c.lookupNames(true)
}

func (c *Client) lookupNames(refresh bool) (map[string]string, error) {
	c.names.mu.Lock()
	defer c.names.mu.Unlock()
	if c.names.byName != nil {
		if !refresh || time.Since(c.names.listedAt) < c.names.refreshFloor() {
			return c.names.byName, nil
		}
	}
	index, err := c.listNames()
	if err != nil {
		// Not kept: the next call lists again.
		return nil, err
	}
	c.names.byName = index
	c.names.listedAt = time.Now()
	return index, nil
}

// listNames asks the platform for the secrets this identity may see.
func (c *Client) listNames() (map[string]string, error) {
	resp, err := c.authedGet(c.platformURL + "/api/v1/nhi-agent/secrets")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("transit: list secrets: HTTP %d: %s", resp.StatusCode, body)
	}
	var payload struct {
		Data []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, fmt.Errorf("transit: decode secrets: %w", err)
	}
	index := make(map[string]string, len(payload.Data))
	for _, s := range payload.Data {
		index[s.Name] = s.ID
	}
	return index, nil
}

// getSecretDirect fetches one secret's value from the platform.
func (c *Client) getSecretDirect(name string) (string, error) {
	index, err := c.resolveNames()
	if err != nil {
		return "", err
	}
	id, found := index[name]
	if !found {
		// Granted or created since the index was listed, perhaps.
		if index, err = c.refreshNames(); err != nil {
			return "", err
		}
		id, found = index[name]
	}
	if !found {
		// Not found and not permitted are the same answer here, because the
		// listing is already narrowed by grants. Saying which would tell a caller
		// whether a secret it cannot have exists.
		return "", fmt.Errorf("transit: no secret %q is available to this identity", name)
	}

	resp, err := c.authedGet(c.platformURL + "/api/v1/nhi-agent/secrets/" + id)
	if err != nil {
		return "", err
	}
	if resp.StatusCode == http.StatusNotFound {
		// The id is gone; the secret may have been recreated under a new one.
		// Ask once more by the new id, if the listing has one.
		resp.Body.Close()
		index, err = c.refreshNames()
		if err != nil {
			return "", err
		}
		newID, ok := index[name]
		if !ok {
			return "", fmt.Errorf("transit: no secret %q is available to this identity", name)
		}
		if newID == id {
			return "", fmt.Errorf("transit: get secret %q: HTTP %d", name, http.StatusNotFound)
		}
		if resp, err = c.authedGet(c.platformURL + "/api/v1/nhi-agent/secrets/" + newID); err != nil {
			return "", err
		}
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("transit: get secret %q: HTTP %d: %s", name, resp.StatusCode, body)
	}
	var payload struct {
		Value string `json:"value"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return "", fmt.Errorf("transit: decode secret: %w", err)
	}
	// The platform returns the value base64 encoded; the caller wants what was
	// stored.
	raw, err := base64.StdEncoding.DecodeString(payload.Value)
	if err != nil {
		return "", fmt.Errorf("transit: decode secret value: %w", err)
	}
	return string(raw), nil
}

// listSecretsDirect names what this identity may read.
func (c *Client) listSecretsDirect() ([]Secret, error) {
	index, err := c.resolveNames()
	if err != nil {
		return nil, err
	}
	out := make([]Secret, 0, len(index))
	for name := range index {
		out = append(out, Secret{Name: name})
	}
	return out, nil
}

// Resolve checks that every name is available to this identity, and is how an
// application makes a missing grant a startup failure rather than a surprise
// later.
//
// Reports every missing name at once, because an operator fixing one grant
// wants to know about the rest before redeploying.
//
// Works in both modes, which it did not. It returned nil immediately whenever a
// connector was configured -- the mode the delivery model is actually about --
// so the check an application was told to rely on at startup could not fail, and
// a missing grant surfaced at three in the morning exactly as intended to be
// prevented. Direct mode resolves against the platform; with a connector it also
// asks the connector for each envelope, because a name the identity may unwrap
// but no connector is granted to cache is just as broken at run time and the
// whole point is to find that out at deploy time.
func (c *Client) Resolve(names ...string) error {
	if len(names) == 0 {
		return nil
	}

	index, err := c.resolveNames()
	if err != nil {
		return err
	}

	for _, n := range names {
		if _, found := index[n]; !found {
			// A grant made since the index was listed should not fail startup.
			if index, err = c.refreshNames(); err != nil {
				return err
			}
			break
		}
	}

	var missing, uncached []string
	for _, n := range names {
		if _, found := index[n]; !found {
			missing = append(missing, n)
			continue
		}
		if c.url == "" {
			continue
		}
		// The connector half. Checked without unwrapping anything: an envelope
		// this application cannot be handed is a deployment fault whether or not
		// the key would have been given.
		if _, err := c.fetchEnvelope(n, false); err != nil {
			uncached = append(uncached, n)
		}
	}

	if len(missing) > 0 {
		return fmt.Errorf("transit: no secret available to this identity: %s",
			strings.Join(missing, ", "))
	}
	if len(uncached) > 0 {
		return fmt.Errorf("transit: the connector holds no envelope for: %s "+
			"(the identity may unwrap them, but no connector is granted to cache them)",
			strings.Join(uncached, ", "))
	}
	return nil
}
