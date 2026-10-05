package transit

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Leased credentials: a credential issued for a while, kept alive while it is in
// use, and handed back when it is not.
//
// This is the other half of what a short-lived credential needs. A secret that
// rotates is followed by re-reading it; a leased credential expires, and the
// holder is the only party that knows it is still needed. CoreLink has had the
// endpoints since v1.24.4 and no SDK could call them, so an application's only
// options were to watch its database credential die or to ask for a long enough
// TTL that the shortness stopped meaning anything.
//
// Renewal bounds itself. CoreLink refuses past a maximum lifetime or a maximum
// number of renewals, so keeping a credential alive for as long as it is used is
// not the same as keeping it forever -- which is why KeepAlive is safe to run in
// the background, and why it stops rather than retrying when it is refused.
//
// See docs/secret-delivery.md.

// Resource types a credential can be leased against.
const (
	ResourceSecret   = "secret"
	ResourceDatabase = "database"
	ResourceCloud    = "cloud"
)

// ErrLeaseExhausted means this lease will not extend again.
//
// Distinct from an ordinary failure because the recovery is different: the
// credential has reached its maximum lifetime or its renewal limit, so retrying
// is pointless and the application should request a new one. CoreLink does not
// say which limit was reached, and the action is the same either way.
var ErrLeaseExhausted = errors.New("this credential cannot be extended further")

// ErrLeaseNotFound means the lease is unknown, already revoked, or belongs to
// another identity -- which are deliberately indistinguishable.
var ErrLeaseNotFound = errors.New("lease not found")

// Lease is a credential and the terms it was issued under.
type Lease struct {
	// ID is what renewal and release name.
	ID string `json:"lease_id"`
	// Credential is the issued material, as CoreLink sends it: a string.
	//
	// What is inside depends on the resource. For a secret it is the stored
	// record, so an application that wants a field out of it parses it; for
	// other resource types it is whatever that vendor issues. Typed as a map
	// here until a live call proved otherwise -- the fake beside this agreed
	// with the guess, which is the argument for the e2e test.
	Credential string    `json:"credential"`
	ExpiresAt  time.Time `json:"expires_at"`
	IssuedAt   time.Time `json:"issued_at"`
}

// Remaining is how long this lease has left, as last known.
//
// Computed from ExpiresAt rather than tracked, so a renewal that this process
// did not make is not reflected -- ask CoreLink if that matters.
func (l Lease) Remaining() time.Duration {
	if l.ExpiresAt.IsZero() {
		return 0
	}
	return time.Until(l.ExpiresAt)
}

// String redacts the credential.
//
// A lease is logged while debugging far more often than a secret is, because it
// has a lifecycle worth tracing, so its default rendering must not be where the
// credential escapes.
func (l Lease) String() string {
	return fmt.Sprintf("Lease{ID: %s, ExpiresAt: %s, Credential: <redacted>}",
		l.ID, l.ExpiresAt.Format(time.RFC3339))
}

// RequestCredential asks CoreLink for a credential leased for a while.
//
// resourceType is one of ResourceSecret, ResourceDatabase or ResourceCloud, and
// resourceID names the thing to issue against. A zero ttl takes CoreLink's
// default; asking for longer than policy allows is CoreLink's decision, not
// this one's, and what comes back says how long was actually granted.
//
// Authorized by the identity's own grants on that resource. This is a platform
// call, so it goes through the connector's tunnel when one is configured.
func (c *Client) RequestCredential(resourceType, resourceID string, ttl time.Duration) (Lease, error) {
	if c.platformURL == "" || c.nhiID == "" {
		return Lease{}, fmt.Errorf("transit: RequestCredential needs an identity; set PlatformURL and NHIID")
	}
	switch resourceType {
	case ResourceSecret, ResourceDatabase, ResourceCloud:
	default:
		return Lease{}, fmt.Errorf("transit: resource type %q is not one of %q, %q, %q",
			resourceType, ResourceSecret, ResourceDatabase, ResourceCloud)
	}
	if resourceID == "" {
		return Lease{}, fmt.Errorf("transit: a resource id is required")
	}

	body := map[string]interface{}{
		"resource_type": resourceType,
		"resource_id":   resourceID,
	}
	if ttl > 0 {
		body["ttl_seconds"] = int(ttl.Seconds())
	}

	resp, err := c.platformPost(c.platformURL+"/api/v1/nhi-agent/credentials", body)
	if err != nil {
		return Lease{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return Lease{}, fmt.Errorf("transit: CoreLink refused to issue a credential: %w", httpError(resp))
	}

	var lease Lease
	if err := json.NewDecoder(resp.Body).Decode(&lease); err != nil {
		return Lease{}, fmt.Errorf("transit: decoding the lease: %w", err)
	}
	if lease.ID == "" {
		return Lease{}, fmt.Errorf("transit: CoreLink issued a credential with no lease id")
	}
	return lease, nil
}

// RenewLease extends a lease, or says why it will not extend.
//
// Returns ErrLeaseExhausted when the credential has reached its maximum lifetime
// or its renewal limit. That is not a failure to retry: request a new credential
// instead.
func (c *Client) RenewLease(leaseID string) error {
	if c.platformURL == "" || c.nhiID == "" {
		return fmt.Errorf("transit: RenewLease needs an identity; set PlatformURL and NHIID")
	}
	if leaseID == "" {
		return fmt.Errorf("transit: a lease id is required")
	}

	resp, err := c.platformPost(
		c.platformURL+"/api/v1/nhi-agent/leases/"+url.PathEscape(leaseID)+"/renew", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		return nil
	case http.StatusUnprocessableEntity:
		return ErrLeaseExhausted
	case http.StatusNotFound:
		return ErrLeaseNotFound
	default:
		return fmt.Errorf("transit: renewing the lease: %w", httpError(resp))
	}
}

// ReleaseCredential hands a credential back before it expires.
//
// Worth doing rather than letting it lapse: the credential stops working at
// once, which closes the window between finishing with it and its expiry. A
// lease that is already gone is not an error, because the caller's intent is
// satisfied either way.
func (c *Client) ReleaseCredential(leaseID string) error {
	if c.platformURL == "" || c.nhiID == "" {
		return fmt.Errorf("transit: ReleaseCredential needs an identity; set PlatformURL and NHIID")
	}
	if leaseID == "" {
		return fmt.Errorf("transit: a lease id is required")
	}

	req, err := http.NewRequest(http.MethodDelete,
		c.platformURL+"/api/v1/nhi-agent/credentials/"+url.PathEscape(leaseID), nil)
	if err != nil {
		return fmt.Errorf("transit: building the release request: %w", err)
	}
	if err := c.authorize(req); err != nil {
		return err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("transit: reaching CoreLink to release: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusNoContent, http.StatusOK, http.StatusNotFound:
		// Already gone counts as released.
		return nil
	default:
		return fmt.Errorf("transit: releasing the credential: %w", httpError(resp))
	}
}

// ListLeases returns the identity's active leases.
//
// Useful after a restart: a process that lost track of what it holds can find
// out rather than requesting more and leaving the old ones to expire.
func (c *Client) ListLeases() ([]Lease, error) {
	if c.platformURL == "" || c.nhiID == "" {
		return nil, fmt.Errorf("transit: ListLeases needs an identity; set PlatformURL and NHIID")
	}

	req, err := http.NewRequest(http.MethodGet, c.platformURL+"/api/v1/nhi-agent/credentials", nil)
	if err != nil {
		return nil, fmt.Errorf("transit: building the list request: %w", err)
	}
	if err := c.authorize(req); err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("transit: reaching CoreLink to list leases: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("transit: listing leases: %w", httpError(resp))
	}

	// The listing returns lease records rather than credentials: the material is
	// handed over once, at issue, and is not retrievable afterwards.
	// "data", which is what the platform actually sends. This read "leases"
	// until it was pointed at a running CoreLink: the handler's own variable is
	// called leases, and the fake written from reading that code agreed with the
	// mistake. Only the real thing disagreed.
	var payload struct {
		Leases []struct {
			ID        string    `json:"id"`
			ExpiresAt time.Time `json:"expires_at"`
			IssuedAt  time.Time `json:"issued_at"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, fmt.Errorf("transit: decoding the lease list: %w", err)
	}

	out := make([]Lease, 0, len(payload.Leases))
	for _, l := range payload.Leases {
		out = append(out, Lease{ID: l.ID, ExpiresAt: l.ExpiresAt, IssuedAt: l.IssuedAt})
	}
	return out, nil
}

// KeepAlive renews a lease in the background for as long as it is in use.
//
// Renews at half the remaining life, so a missed attempt has another before the
// credential lapses, and stops when CoreLink refuses -- which it does past the
// maximum lifetime or renewal count. So this keeps a credential alive while it
// is needed; it cannot keep one alive forever, because the bound is CoreLink's
// and not this process's.
//
// onExpiry, when given, is called once with the reason renewal stopped. That is
// how an application learns it must request a new credential, which is the one
// thing it cannot be told by a renewal that simply stopped happening.
//
// Call the returned stop function when the credential is no longer in use. It
// does not release the lease; ReleaseCredential does that, and doing both is the
// tidy ending.
func (c *Client) KeepAlive(lease Lease, onExpiry func(error)) (stop func()) {
	done := make(chan struct{})
	var once sync.Once
	stop = func() { once.Do(func() { close(done) }) }

	go func() {
		expiresAt := lease.ExpiresAt
		for {
			wait := time.Until(expiresAt) / 2
			if floor := c.keepAliveFloor(); wait < floor {
				// Either the lease is nearly up or CoreLink gave no expiry.
				// Either way, do not spin.
				wait = floor
			}

			select {
			case <-done:
				return
			case <-time.After(wait):
			}

			err := c.RenewLease(lease.ID)
			if err != nil {
				if onExpiry != nil {
					onExpiry(err)
				}
				return
			}

			// CoreLink does not say the new expiry, so the next wait is measured
			// from the original term. Asking again is a round trip for something
			// the lease's own TTL already implies.
			expiresAt = time.Now().Add(lease.ExpiresAt.Sub(lease.IssuedAt))
			if lease.ExpiresAt.IsZero() || lease.IssuedAt.IsZero() {
				expiresAt = time.Now().Add(time.Minute)
			}
		}
	}()

	return stop
}

// platformPost sends an authenticated POST to CoreLink.
func (c *Client) platformPost(endpoint string, body interface{}) (*http.Response, error) {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("transit: encoding the request: %w", err)
		}
		reader = strings.NewReader(string(encoded))
	}

	req, err := http.NewRequest(http.MethodPost, endpoint, reader)
	if err != nil {
		return nil, fmt.Errorf("transit: building the request: %w", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if err := c.authorize(req); err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("transit: reaching CoreLink: %w", err)
	}
	return resp, nil
}

// authorize puts the current session on a platform request.
func (c *Client) authorize(req *http.Request) error {
	c.sessionMu.Lock()
	session := c.sessionID
	c.sessionMu.Unlock()
	if session == "" {
		return fmt.Errorf("transit: no CoreLink session; call Bootstrap first")
	}
	req.Header.Set("X-NHI-Session", session)
	return nil
}

// httpError summarises a failed response without quoting it at length.
func httpError(resp *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
}

// keepAliveFloor is the shortest interval KeepAlive will wait between renewals.
//
// A second in production, so a lease with no expiry or one already nearly up
// cannot make this spin. Lowered by tests, which would otherwise spend a second
// per renewal proving timing that is not what they are checking.
func (c *Client) keepAliveFloor() time.Duration {
	if c.renewFloor > 0 {
		return c.renewFloor
	}
	return time.Second
}
