package transit

import (
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInvalidCACertFileFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name string
		data *string
	}{
		{name: "missing"},
		{name: "invalid PEM", data: func() *string { s := "not a pem"; return &s }()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			caFile := filepath.Join(t.TempDir(), "ca.pem")
			if tc.data != nil {
				if err := os.WriteFile(caFile, []byte(*tc.data), 0600); err != nil {
					t.Fatal(err)
				}
			}
			requests := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests++
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()

			c := New(Options{TransitURL: server.URL, PlatformURL: server.URL, NHIID: "test", CACertFile: caFile})
			if err := c.Bootstrap(); err == nil {
				t.Fatal("Bootstrap succeeded with an invalid CA file")
			}
			if _, err := c.GetSecretSealed("production/db"); err == nil {
				t.Fatal("GetSecretSealed succeeded with an invalid CA file")
			} else if !strings.Contains(err.Error(), "CA certificate file") {
				t.Errorf("GetSecretSealed error = %v, want CA file error", err)
			}
			if requests != 0 {
				t.Errorf("server received %d requests, want none", requests)
			}
		})
	}
}

func TestValidCACertFileWorks(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	caFile := filepath.Join(t.TempDir(), "ca.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	if err := os.WriteFile(caFile, certPEM, 0600); err != nil {
		t.Fatal(err)
	}
	c := New(Options{TransitURL: server.URL, CACertFile: caFile})
	resp, err := c.httpClient.Get(server.URL)
	if err != nil {
		t.Fatalf("request with configured CA failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusNoContent)
	}
}
