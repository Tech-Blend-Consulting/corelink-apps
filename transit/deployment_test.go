package transit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTheDeploymentFileIsRead(t *testing.T) {
	d, err := parseDeployment(`# the orders service
nhiId:          11111111-2222-3333-4444-555555555555
serviceAccount: orders
secrets:
  - production/dbone
  - production/apikey
`)
	if err != nil {
		t.Fatalf("a well formed file did not parse: %v", err)
	}
	if d.NHIID != "11111111-2222-3333-4444-555555555555" {
		t.Errorf("nhiId = %q", d.NHIID)
	}
	if d.ServiceAccount != "orders" {
		t.Errorf("serviceAccount = %q", d.ServiceAccount)
	}
	// File order, because the application asked in that order and a startup
	// failure should name them the way its author wrote them.
	want := []string{"production/dbone", "production/apikey"}
	if strings.Join(d.Secrets, ",") != strings.Join(want, ",") {
		t.Errorf("secrets = %v, want %v", d.Secrets, want)
	}
}

func TestTheSingleSecretFormIsRead(t *testing.T) {
	// The shape in the design doc, which names one secret inline.
	d, err := parseDeployment("nhiId: abc\nsecrets: production/dbone\n")
	if err != nil {
		t.Fatalf("the inline form did not parse: %v", err)
	}
	if len(d.Secrets) != 1 || d.Secrets[0] != "production/dbone" {
		t.Errorf("secrets = %v", d.Secrets)
	}
}

// The shared cases, which every SDK parses and must agree on.
//
// Six hand-written readers drift unless one thing pins them. This is that
// thing: sdk/testdata/deployment_cases.json carries the accepted files with
// their expected result and the rejected files that must be refused, and each
// SDK runs the same list. A reader that quietly disagrees with the other five
// about which secrets an application asked for is the failure worth preventing.
func TestTheSharedDeploymentCases(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "testdata", "deployment_cases.json"))
	if err != nil {
		t.Fatalf("reading the shared cases: %v", err)
	}
	var cases struct {
		Accepted []struct {
			Name           string   `json:"name"`
			Text           string   `json:"text"`
			NHIID          string   `json:"nhiId"`
			ServiceAccount string   `json:"serviceAccount"`
			Secrets        []string `json:"secrets"`
		} `json:"accepted"`
		Rejected []struct {
			Name string `json:"name"`
			Text string `json:"text"`
		} `json:"rejected"`
	}
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatalf("parsing the shared cases: %v", err)
	}
	if len(cases.Accepted) == 0 || len(cases.Rejected) == 0 {
		t.Fatal("the shared cases are empty")
	}

	for _, tc := range cases.Accepted {
		t.Run("accepted/"+tc.Name, func(t *testing.T) {
			d, err := loadDeploymentText(tc.Text)
			if err != nil {
				t.Fatalf("refused a file the other SDKs accept: %v", err)
			}
			if d.NHIID != tc.NHIID {
				t.Errorf("nhiId = %q, want %q", d.NHIID, tc.NHIID)
			}
			if d.ServiceAccount != tc.ServiceAccount {
				t.Errorf("serviceAccount = %q, want %q", d.ServiceAccount, tc.ServiceAccount)
			}
			if strings.Join(d.Secrets, ",") != strings.Join(tc.Secrets, ",") {
				t.Errorf("secrets = %v, want %v", d.Secrets, tc.Secrets)
			}
		})
	}

	for _, tc := range cases.Rejected {
		t.Run("rejected/"+tc.Name, func(t *testing.T) {
			if _, err := loadDeploymentText(tc.Text); err == nil {
				t.Error("accepted a file the other SDKs refuse; it should fail rather than " +
					"be read as something its author did not write")
			}
		})
	}
}

// loadDeploymentText runs the whole load, including the required-field checks,
// so the shared cases exercise what an application actually calls.
func loadDeploymentText(text string) (*Deployment, error) {
	dir, err := os.MkdirTemp("", "deployment")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	p := filepath.Join(dir, "secrets.yaml")
	if err := os.WriteFile(p, []byte(text), 0o600); err != nil {
		return nil, err
	}
	return LoadDeployment(p)
}

func TestQuotedValuesAreUnwrapped(t *testing.T) {
	d, err := parseDeployment("nhiId: \"abc\"\nserviceAccount: 'orders'\nsecrets:\n  - \"production/one\"\n")
	if err != nil {
		t.Fatalf("quoted values did not parse: %v", err)
	}
	if d.NHIID != "abc" || d.ServiceAccount != "orders" || d.Secrets[0] != "production/one" {
		t.Errorf("got %+v", d)
	}
}

func TestAQuotedColonIsStillAllowed(t *testing.T) {
	// Refusing the ambiguous form is right; refusing the explicit one would be
	// a parser that cannot express a legal name.
	d, err := parseDeployment("nhiId: a\nsecrets: \"prod:one\"\n")
	if err != nil {
		t.Fatalf("a quoted colon was refused: %v", err)
	}
	if d.Secrets[0] != "prod:one" {
		t.Errorf("secrets = %v", d.Secrets)
	}
}

func TestAFileMustNameAnIdentityAndSomethingToAskFor(t *testing.T) {
	dir := t.TempDir()

	t.Run("no nhiId", func(t *testing.T) {
		p := filepath.Join(dir, "no-id.yaml")
		os.WriteFile(p, []byte("secrets: production/one\n"), 0o600)
		if _, err := LoadDeployment(p); err == nil {
			t.Error("a file naming no identity was accepted")
		}
	})

	t.Run("no secrets", func(t *testing.T) {
		p := filepath.Join(dir, "no-secrets.yaml")
		os.WriteFile(p, []byte("nhiId: abc\n"), 0o600)
		if _, err := LoadDeployment(p); err == nil {
			t.Error("a file naming nothing to ask for was accepted")
		}
	})
}

func TestAMissingFileIsNotAnErrorForTheOptionalLoader(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "absent.yaml")

	d, err := LoadDeploymentIfPresent(missing)
	if err != nil {
		t.Fatalf("a missing file was an error: %v", err)
	}
	if d != nil {
		t.Errorf("a missing file produced a deployment: %+v", d)
	}

	t.Run("but a file that does not parse still is", func(t *testing.T) {
		// "No file" and "a file I could not read" are different, and running the
		// application on a configuration nobody wrote is the wrong recovery.
		p := filepath.Join(t.TempDir(), "broken.yaml")
		os.WriteFile(p, []byte("nhiId: a\nsecrets: [one]\n"), 0o600)
		if _, err := LoadDeploymentIfPresent(p); err == nil {
			t.Error("an unparseable file was treated as absent")
		}
	})
}

func TestTheEnvironmentOverridesThePath(t *testing.T) {
	p := filepath.Join(t.TempDir(), "elsewhere.yaml")
	os.WriteFile(p, []byte("nhiId: abc\nsecrets: production/one\n"), 0o600)
	t.Setenv(DeploymentPathEnv, p)

	d, err := LoadDeployment("")
	if err != nil {
		t.Fatalf("the override was not used: %v", err)
	}
	if d.Path != p {
		t.Errorf("read %q, want %q", d.Path, p)
	}
}

// The ServiceAccount check is a misconfiguration catch, so what matters is that
// it only speaks when it can see a disagreement.
func TestTheServiceAccountCheckOnlySpeaksWhenItCanSeeADisagreement(t *testing.T) {
	t.Run("no serviceAccount named: no opinion", func(t *testing.T) {
		d := &Deployment{NHIID: "a", Secrets: []string{"one"}}
		if err := d.VerifyServiceAccount(); err != nil {
			t.Errorf("it objected with nothing to compare: %v", err)
		}
	})

	t.Run("no projected token: no opinion", func(t *testing.T) {
		// Not running under Kubernetes, which is the ordinary case for a host.
		d := &Deployment{NHIID: "a", ServiceAccount: "orders", Secrets: []string{"one"}}
		if err := d.VerifyServiceAccount(); err != nil {
			t.Errorf("it objected outside Kubernetes: %v", err)
		}
	})

	t.Run("it reads the name out of a projected token", func(t *testing.T) {
		// A token's claims, as the kubelet writes them. The signature is not
		// checked and is not what this concludes anything from.
		payload := `{"kubernetes.io":{"serviceaccount":{"name":"orders"}},` +
			`"sub":"system:serviceaccount:prod:orders"}`
		token := "x." + rawURL(payload) + ".y"
		got, ok := serviceAccountFromToken(token)
		if !ok || got != "orders" {
			t.Errorf("got %q ok=%v, want orders", got, ok)
		}
	})

	t.Run("it falls back to the subject", func(t *testing.T) {
		token := "x." + rawURL(`{"sub":"system:serviceaccount:prod:billing"}`) + ".y"
		got, ok := serviceAccountFromToken(token)
		if !ok || got != "billing" {
			t.Errorf("got %q ok=%v, want billing", got, ok)
		}
	})

	t.Run("junk is no opinion rather than an error", func(t *testing.T) {
		if _, ok := serviceAccountFromToken("not-a-token"); ok {
			t.Error("it claimed to read a name out of junk")
		}
	})
}

func rawURL(s string) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	var out strings.Builder
	data := []byte(s)
	for i := 0; i < len(data); i += 3 {
		var b [3]byte
		n := copy(b[:], data[i:])
		out.WriteByte(alphabet[b[0]>>2])
		out.WriteByte(alphabet[(b[0]&0x03)<<4|b[1]>>4])
		if n > 1 {
			out.WriteByte(alphabet[(b[1]&0x0f)<<2|b[2]>>6])
		}
		if n > 2 {
			out.WriteByte(alphabet[b[2]&0x3f])
		}
	}
	return out.String()
}
