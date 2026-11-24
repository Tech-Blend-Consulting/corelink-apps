package transit

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func newConnectTestClient(t *testing.T, url string) *Client {
	t.Helper()
	c := New(Options{
		NHIID:       "nhi-test",
		PlatformURL: url,
		Attest:      func() (string, string, error) { return "test", "evidence", nil },
	})
	t.Cleanup(c.Close)
	return c
}

func TestReconnectStartsRefreshLoopOnce(t *testing.T) {
	var connects atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/nhi-agent/connect" {
			n := connects.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]string{"session_id": "s" + strconv.Itoa(int(n)), "status": "active"})
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	c := newConnectTestClient(t, srv.URL)
	if err := c.Bootstrap(); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	for i := 0; i < 5; i++ {
		if err := c.nhiConnect(); err != nil {
			t.Fatalf("reconnect: %v", err)
		}
	}
	if got := c.loopStarts.Load(); got != 1 {
		t.Fatalf("refresh loops started = %d, want 1", got)
	}
}

func TestConcurrentReconnectsShareOneConnect(t *testing.T) {
	var connects atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/nhi-agent/connect" {
			n := connects.Add(1)
			time.Sleep(50 * time.Millisecond)
			_ = json.NewEncoder(w).Encode(map[string]string{"session_id": "s" + strconv.Itoa(int(n)), "status": "active"})
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	c := newConnectTestClient(t, srv.URL)
	c.sessionID = "stale"

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := c.nhiConnect(); err != nil {
				t.Errorf("connect: %v", err)
			}
		}()
	}
	wg.Wait()
	if got := connects.Load(); got != 1 {
		t.Fatalf("connect POSTs = %d, want 1", got)
	}
}

func TestCloseInterruptsApprovalPoll(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/nhi-agent/connect" {
			_ = json.NewEncoder(w).Encode(map[string]string{"session_id": "pending-1", "status": "pending_approval"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "pending_approval"})
	}))
	defer srv.Close()

	c := newConnectTestClient(t, srv.URL)
	c.pollEvery = time.Hour

	done := make(chan error, 1)
	go func() { done <- c.nhiConnect() }()
	time.Sleep(50 * time.Millisecond)
	close(c.stopCh)

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("connect succeeded after close, want error")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("approval poll did not stop on Close")
	}
}
