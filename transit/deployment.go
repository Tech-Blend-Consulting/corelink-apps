package transit

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// The deployment file: what an application was configured to ask for.
//
//	nhiId:          11111111-2222-3333-4444-555555555555
//	serviceAccount: orders
//	secrets:
//	  - production/dbone
//	  - production/apikey
//
// It tells the SDK which identity to attest as and which secrets to ask for.
// That is all it is.
//
// **Nothing in it grants anything**, and that must stay true even when somebody
// proposes provisioning grants from it as a convenience. Anyone who can edit a
// Deployment can add a path to this file; if that provisioned access, "edit
// deployments" would quietly become "read any secret". The file is a request.
// The grant on the NHI is the only answer, and it is checked by CoreLink on
// every call regardless of what is written here.
//
// Neither value is sensitive. The NHI id is a pointer, not a credential:
// Connect looks the identity up by the id presented and then verifies the
// evidence against *that identity's* binding, so an application naming someone
// else's id and attesting with its own ServiceAccount fails the claim match.
//
// It also means an application asks for what it was configured to ask for,
// rather than discovering what exists.

// DefaultDeploymentPath is where the file is looked for when no path is given.
const DefaultDeploymentPath = "/etc/corelink/secrets.yaml"

// DeploymentPathEnv overrides the default path.
const DeploymentPathEnv = "CORELINK_DEPLOYMENT_FILE"

// Deployment is a parsed deployment file.
type Deployment struct {
	// NHIID is the identity to attest as.
	NHIID string
	// ServiceAccount is the Kubernetes ServiceAccount the deployment expects to
	// be running as. Descriptive, not authoritative -- see VerifyServiceAccount.
	ServiceAccount string
	// Secrets are the names to ask for, in file order.
	Secrets []string
	// Path is where this was read from, for error messages.
	Path string
}

// LoadDeployment reads the deployment file.
//
// path may be empty, in which case CORELINK_DEPLOYMENT_FILE is used, and failing
// that DefaultDeploymentPath.
func LoadDeployment(path string) (*Deployment, error) {
	if path == "" {
		path = os.Getenv(DeploymentPathEnv)
	}
	if path == "" {
		path = DefaultDeploymentPath
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("transit: reading the deployment file %s: %w", path, err)
	}

	d, err := parseDeployment(string(data))
	if err != nil {
		return nil, fmt.Errorf("transit: %s: %w", path, err)
	}
	d.Path = path

	if d.NHIID == "" {
		return nil, fmt.Errorf("transit: %s: nhiId is required; it names the identity to attest as", path)
	}
	if len(d.Secrets) == 0 {
		return nil, fmt.Errorf("transit: %s: secrets is required; an application asks for what it was "+
			"configured to ask for rather than discovering what exists", path)
	}
	return d, nil
}

// LoadDeploymentIfPresent is LoadDeployment, except that a missing file is not
// an error.
//
// For an application that can be configured either way: the file when it is
// deployed with one, its own configuration otherwise. A file that exists and
// does not parse is still an error -- the difference that matters is "no file"
// against "a file I could not read", and silently ignoring the second would run
// the application on a configuration nobody wrote.
func LoadDeploymentIfPresent(path string) (*Deployment, error) {
	lookIn := path
	if lookIn == "" {
		lookIn = os.Getenv(DeploymentPathEnv)
	}
	if lookIn == "" {
		lookIn = DefaultDeploymentPath
	}
	if _, err := os.Stat(lookIn); os.IsNotExist(err) {
		return nil, nil
	}
	return LoadDeployment(lookIn)
}

// parseDeployment reads the one shape this file has, and refuses the rest.
//
// Deliberately not a YAML parser. YAML is a large language -- anchors, flow
// collections, multi-line scalars, implicit typing -- and almost all of it is
// ways for a file to mean something other than it appears to. What is needed
// here is three keys, so everything else is refused rather than guessed at.
// A file using a feature this does not implement fails loudly instead of being
// read as something its author did not write, which is the safe direction: this
// file decides which secrets an application asks for.
//
// Accepted: blank lines, # comments, "key: value" at the left margin, and
// "  - item" list entries beneath a key. A scalar may be wrapped in matching
// single or double quotes.
func parseDeployment(text string) (*Deployment, error) {
	d := &Deployment{}
	seen := map[string]bool{}
	var listKey string

	for n, raw := range strings.Split(text, "\n") {
		line := n + 1

		if strings.ContainsRune(raw, '\t') {
			return nil, fmt.Errorf("line %d: tabs are not allowed in indentation", line)
		}
		// A comment is only a comment at the start of a line here. Stripping a
		// trailing "#" would corrupt any value that legitimately contains one.
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.HasPrefix(trimmed, "---") || strings.HasPrefix(trimmed, "...") {
			return nil, fmt.Errorf("line %d: multiple documents are not supported", line)
		}
		if strings.ContainsAny(trimmed, "&*") {
			return nil, fmt.Errorf("line %d: anchors and aliases are not supported", line)
		}

		// A list entry, which belongs to the key above it.
		if strings.HasPrefix(trimmed, "- ") || trimmed == "-" {
			if listKey == "" {
				return nil, fmt.Errorf("line %d: a list entry with no key above it", line)
			}
			item, err := scalar(strings.TrimSpace(strings.TrimPrefix(trimmed, "-")), line)
			if err != nil {
				return nil, err
			}
			if item == "" {
				return nil, fmt.Errorf("line %d: an empty list entry", line)
			}
			if listKey != "secrets" {
				return nil, fmt.Errorf("line %d: %q does not take a list", line, listKey)
			}
			d.Secrets = append(d.Secrets, item)
			continue
		}

		// Anything else must be a key at the left margin. An indented key would
		// be a nested map, which this does not represent. Leading whitespace is
		// what makes it indented; trailing whitespace is invisible and harmless,
		// and comparing the whole line against its trimmed form refused a file
		// over a space nobody could see.
		if strings.TrimLeft(raw, " ") != raw {
			return nil, fmt.Errorf("line %d: unexpected indentation; this file is a flat set of keys", line)
		}
		key, value, found := strings.Cut(trimmed, ":")
		if !found {
			return nil, fmt.Errorf("line %d: expected \"key: value\"", line)
		}
		// YAML needs a space after the colon to make this a mapping at all --
		// "nhiId:abc" is a plain scalar, not a key. Splitting on the colon
		// regardless would read a line YAML does not read that way, which is
		// exactly the kind of quiet disagreement this parser exists to avoid.
		if value != "" && !strings.HasPrefix(value, " ") {
			return nil, fmt.Errorf("line %d: a key needs a space after its colon", line)
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)

		if seen[key] {
			// Two values for one key: a reader has to pick, and either choice is
			// somebody's surprise.
			return nil, fmt.Errorf("line %d: %q appears more than once", line, key)
		}
		seen[key] = true
		listKey = ""

		switch key {
		case "nhiId", "nhiID", "nhi_id":
			v, err := scalar(value, line)
			if err != nil {
				return nil, err
			}
			d.NHIID = v
		case "serviceAccount", "service_account":
			v, err := scalar(value, line)
			if err != nil {
				return nil, err
			}
			d.ServiceAccount = v
		case "secrets":
			if value == "" {
				// The list form; entries follow on their own lines.
				listKey = "secrets"
				continue
			}
			v, err := scalar(value, line)
			if err != nil {
				return nil, err
			}
			d.Secrets = append(d.Secrets, v)
		default:
			// Refused rather than ignored. A typo in a key an application relies
			// on would otherwise be silence, and the application would run asking
			// for nothing.
			return nil, fmt.Errorf("line %d: unknown key %q", line, key)
		}
	}

	return d, nil
}

// scalar reads one plain value, refusing the YAML forms this does not implement.
func scalar(v string, line int) (string, error) {
	if v == "" {
		return "", nil
	}
	if strings.HasPrefix(v, "[") || strings.HasPrefix(v, "{") {
		return "", fmt.Errorf("line %d: flow collections are not supported; use a \"- item\" list", line)
	}
	if v == "|" || v == ">" || strings.HasPrefix(v, "|") || strings.HasPrefix(v, ">") {
		return "", fmt.Errorf("line %d: multi-line scalars are not supported", line)
	}
	if len(v) >= 2 {
		first, last := v[0], v[len(v)-1]
		if (first == '"' && last == '"') || (first == '\'' && last == '\'') {
			inner := v[1 : len(v)-1]
			if strings.ContainsRune(inner, rune(first)) {
				return "", fmt.Errorf("line %d: escapes inside a quoted value are not supported", line)
			}
			return inner, nil
		}
		if first == '"' || first == '\'' {
			return "", fmt.Errorf("line %d: a quoted value is not closed", line)
		}
	}
	if strings.Contains(v, ": ") || strings.HasSuffix(v, ":") {
		// YAML refuses ": " inside a plain scalar, because it cannot tell the
		// value from a nested mapping. Taking everything after the first colon
		// would accept a line YAML rejects, and read it as a value its author
		// did not write.
		return "", fmt.Errorf("line %d: a value containing a colon must be quoted", line)
	}
	if strings.ContainsRune(v, '#') {
		// Ambiguous: YAML would read " #" as a trailing comment, and a reader
		// that guesses either way is wrong for somebody. Quote it to be explicit.
		return "", fmt.Errorf("line %d: a value containing # must be quoted", line)
	}
	return v, nil
}

// VerifyServiceAccount reports whether the pod is running as the ServiceAccount
// the deployment file names.
//
// **This is a misconfiguration check, not a security control.** It reads the
// projected token's claims without verifying its signature, because nothing it
// concludes is trusted: CoreLink verifies that token properly, against the
// identity's own binding, and that is what decides whether the workload is who
// it says. Re-doing that here would be a second authorization path for one
// decision, which is what rule 11 forbids.
//
// What it is for: a Deployment whose secrets.yaml says one ServiceAccount while
// the pod spec says another is a deployment that will fail at CoreLink with a
// claim mismatch, some time later and somewhere less obvious. Saying so at
// startup turns a confusing refusal into an obvious one.
//
// No file, no ServiceAccount named, or an unreadable token: no opinion, no
// error. It only speaks when it can see a disagreement.
func (d *Deployment) VerifyServiceAccount() error {
	if d == nil || d.ServiceAccount == "" {
		return nil
	}
	const saTokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	token, err := os.ReadFile(saTokenPath)
	if err != nil || len(token) == 0 {
		return nil
	}

	actual, ok := serviceAccountFromToken(string(token))
	if !ok {
		return nil
	}
	if actual != d.ServiceAccount {
		return fmt.Errorf("transit: %s names serviceAccount %q but this pod is running as %q; "+
			"the deployment file and the pod spec disagree",
			d.Path, d.ServiceAccount, actual)
	}
	return nil
}

// serviceAccountFromToken pulls the ServiceAccount name out of a projected
// token's claims. The signature is not checked; see VerifyServiceAccount.
func serviceAccountFromToken(token string) (string, bool) {
	parts := strings.Split(strings.TrimSpace(token), ".")
	if len(parts) != 3 {
		return "", false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", false
	}
	// The subject, which is the canonical and flat form:
	//   system:serviceaccount:<namespace>:<name>
	// Every projected token carries it, so there is no need to reach into the
	// nested kubernetes.io claim for the same name. One rule, and the six SDKs
	// agree by construction rather than by coincidence.
	var claims struct {
		Subject string `json:"sub"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", false
	}
	if parts := strings.Split(claims.Subject, ":"); len(parts) == 4 && parts[0] == "system" {
		return parts[3], true
	}
	return "", false
}
