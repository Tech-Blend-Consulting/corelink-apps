import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * The deployment file: what an application was configured to ask for.
 *
 * <pre>
 * nhiId:          11111111-2222-3333-4444-555555555555
 * serviceAccount: orders
 * secrets:
 *   - production/dbone
 *   - production/apikey
 * </pre>
 *
 * <p>It tells the SDK which identity to attest as and which secrets to ask for. That is all it is.
 *
 * <p><b>Nothing in it grants anything</b>, and that must stay true even when somebody proposes
 * provisioning grants from it as a convenience. Anyone who can edit a Deployment can add a path to
 * this file; if that provisioned access, "edit deployments" would quietly become "read any secret".
 * The file is a request. The grant on the NHI is the only answer, and CoreLink checks it on every
 * call regardless of what is written here.
 *
 * <p>Neither value is sensitive. The NHI id is a pointer, not a credential: Connect looks the
 * identity up by the id presented and then verifies the evidence against <i>that identity's</i>
 * binding, so naming someone else's id and attesting with your own ServiceAccount fails the claim
 * match.
 *
 * <p><b>Deliberately not a YAML parser.</b> YAML is a large language -- anchors, flow collections,
 * multi-line scalars, implicit typing -- and most of it is ways for a file to mean something other
 * than it appears to. Three keys are needed, so everything else is refused rather than guessed at,
 * and the six SDKs then agree with each other rather than each agreeing with whatever YAML library
 * its language happened to ship.
 *
 * <p>Pinned against the other five SDKs by sdk/testdata/deployment_cases.json.
 */
public final class Deployment {

    /** Where the file is looked for when no path is given. */
    public static final String DEFAULT_PATH = "/etc/corelink/secrets.yaml";

    /** Environment variable that overrides the default path. */
    public static final String PATH_ENV = "CORELINK_DEPLOYMENT_FILE";

    private static final String SA_TOKEN_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/token";

    /** A deployment file that could not be read as written. */
    public static class DeploymentException extends RuntimeException {
        public DeploymentException(String message) {
            super(message);
        }
    }

    public String nhiId = "";
    public String serviceAccount = "";
    public final List<String> secrets = new ArrayList<>();
    public String path = "";

    private Deployment() {}

    /** Read the deployment file, throwing if it is missing or unreadable. */
    public static Deployment load(String p) {
        String file = resolvePath(p);
        String text;
        try {
            text = Files.readString(Path.of(file));
        } catch (IOException e) {
            throw new DeploymentException("reading the deployment file " + file + ": " + e.getMessage());
        }

        Deployment d;
        try {
            d = parse(text);
        } catch (DeploymentException e) {
            throw new DeploymentException(file + ": " + e.getMessage());
        }
        d.path = file;

        if (d.nhiId.isEmpty()) {
            throw new DeploymentException(file + ": nhiId is required; it names the identity to attest as");
        }
        if (d.secrets.isEmpty()) {
            throw new DeploymentException(file
                + ": secrets is required; an application asks for what it was configured to ask for "
                + "rather than discovering what exists");
        }
        return d;
    }

    /**
     * load, except that a missing file returns null.
     *
     * <p>A file that exists and does not parse is still an error: the difference that matters is
     * "no file" against "a file I could not read", and silently ignoring the second would run the
     * application on a configuration nobody wrote.
     */
    public static Deployment loadIfPresent(String p) {
        String file = resolvePath(p);
        if (!Files.exists(Path.of(file))) {
            return null;
        }
        return load(file);
    }

    private static String resolvePath(String p) {
        if (p != null && !p.isEmpty()) {
            return p;
        }
        String env = System.getenv(PATH_ENV);
        if (env != null && !env.isEmpty()) {
            return env;
        }
        return DEFAULT_PATH;
    }

    /** Read the one shape this file has, and refuse the rest. */
    public static Deployment parse(String text) {
        Deployment d = new Deployment();
        Set<String> seen = new HashSet<>();
        String listKey = null;

        String[] lines = text.split("\n", -1);
        for (int i = 0; i < lines.length; i++) {
            String raw = lines[i];
            int n = i + 1;

            if (raw.indexOf('\t') >= 0) {
                throw new DeploymentException("line " + n + ": tabs are not allowed in indentation");
            }

            // A comment is only a comment at the start of a line here. Stripping a trailing "#"
            // would corrupt any value that legitimately contains one.
            String trimmed = raw.trim();
            if (trimmed.isEmpty() || trimmed.startsWith("#")) {
                continue;
            }
            if (trimmed.startsWith("---") || trimmed.startsWith("...")) {
                throw new DeploymentException("line " + n + ": multiple documents are not supported");
            }
            if (trimmed.contains("&") || trimmed.contains("*")) {
                throw new DeploymentException("line " + n + ": anchors and aliases are not supported");
            }

            // A list entry, which belongs to the key above it.
            if (trimmed.startsWith("- ") || trimmed.equals("-")) {
                if (listKey == null) {
                    throw new DeploymentException("line " + n + ": a list entry with no key above it");
                }
                String item = scalar(trimmed.substring(1).trim(), n);
                if (item.isEmpty()) {
                    throw new DeploymentException("line " + n + ": an empty list entry");
                }
                if (!listKey.equals("secrets")) {
                    throw new DeploymentException("line " + n + ": " + listKey + " does not take a list");
                }
                d.secrets.add(item);
                continue;
            }

            // Anything else must be a key at the left margin. Leading whitespace is what makes it
            // indented; trailing whitespace is invisible and harmless.
            if (raw.startsWith(" ")) {
                throw new DeploymentException(
                    "line " + n + ": unexpected indentation; this file is a flat set of keys");
            }
            int colon = trimmed.indexOf(':');
            if (colon < 0) {
                throw new DeploymentException("line " + n + ": expected \"key: value\"");
            }
            String key = trimmed.substring(0, colon);
            String value = trimmed.substring(colon + 1);
            // YAML needs a space after the colon to make this a mapping at all -- "nhiId:abc" is a
            // plain scalar, not a key.
            if (!value.isEmpty() && !value.startsWith(" ")) {
                throw new DeploymentException("line " + n + ": a key needs a space after its colon");
            }
            key = key.trim();
            value = value.trim();

            if (!seen.add(key)) {
                // Two values for one key: a reader has to pick, and either choice is somebody's
                // surprise.
                throw new DeploymentException("line " + n + ": " + key + " appears more than once");
            }
            listKey = null;

            switch (key) {
                case "nhiId":
                case "nhiID":
                case "nhi_id":
                    d.nhiId = scalar(value, n);
                    break;
                case "serviceAccount":
                case "service_account":
                    d.serviceAccount = scalar(value, n);
                    break;
                case "secrets":
                    if (value.isEmpty()) {
                        // The list form; entries follow on their own lines.
                        listKey = "secrets";
                        continue;
                    }
                    d.secrets.add(scalar(value, n));
                    break;
                default:
                    // Refused rather than ignored. A typo in a key an application relies on would
                    // otherwise be silence, and the application would run asking for nothing.
                    throw new DeploymentException("line " + n + ": unknown key " + key);
            }
        }

        return d;
    }

    /** Read one plain value, refusing the YAML forms this does not implement. */
    private static String scalar(String v, int n) {
        if (v.isEmpty()) {
            return "";
        }
        if (v.startsWith("[") || v.startsWith("{")) {
            throw new DeploymentException(
                "line " + n + ": flow collections are not supported; use a \"- item\" list");
        }
        if (v.startsWith("|") || v.startsWith(">")) {
            throw new DeploymentException("line " + n + ": multi-line scalars are not supported");
        }
        if (v.length() >= 2) {
            char first = v.charAt(0);
            char last = v.charAt(v.length() - 1);
            if ((first == '"' && last == '"') || (first == '\'' && last == '\'')) {
                String inner = v.substring(1, v.length() - 1);
                if (inner.indexOf(first) >= 0) {
                    throw new DeploymentException(
                        "line " + n + ": escapes inside a quoted value are not supported");
                }
                return inner;
            }
            if (first == '"' || first == '\'') {
                throw new DeploymentException("line " + n + ": a quoted value is not closed");
            }
        } else if (v.equals("\"") || v.equals("'")) {
            throw new DeploymentException("line " + n + ": a quoted value is not closed");
        }
        if (v.contains(": ") || v.endsWith(":")) {
            // YAML refuses ": " inside a plain scalar because it cannot tell the value from a
            // nested mapping.
            throw new DeploymentException("line " + n + ": a value containing a colon must be quoted");
        }
        if (v.contains("#")) {
            // Ambiguous: YAML would read " #" as a trailing comment, and a reader that guesses
            // either way is wrong for somebody.
            throw new DeploymentException("line " + n + ": a value containing # must be quoted");
        }
        return v;
    }

    /**
     * Throw if the pod is not running as the ServiceAccount the file names.
     *
     * <p><b>A misconfiguration check, not a security control.</b> The projected token's claims are
     * read without verifying its signature, because nothing this concludes is trusted: CoreLink
     * verifies that token properly, against the identity's own binding, and that is what decides
     * whether the workload is who it says. Re-deciding it here would be a second authorization path
     * for one question.
     *
     * <p>No name, no token, or an unreadable one: no opinion, no error.
     */
    public void verifyServiceAccount() {
        if (serviceAccount.isEmpty()) {
            return;
        }
        String token;
        try {
            token = Files.readString(Path.of(SA_TOKEN_PATH));
        } catch (IOException e) {
            return;
        }
        String actual = serviceAccountFromToken(token);
        if (actual == null || actual.equals(serviceAccount)) {
            return;
        }
        throw new DeploymentException(path + " names serviceAccount " + serviceAccount
            + " but this pod is running as " + actual
            + "; the deployment file and the pod spec disagree");
    }

    /**
     * The ServiceAccount name from a projected token, or null. The signature is not checked; see
     * {@link #verifyServiceAccount}.
     */
    public static String serviceAccountFromToken(String token) {
        String[] parts = token.trim().split("\\.");
        if (parts.length != 3) {
            return null;
        }
        String json;
        try {
            json = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            return null;
        }
        // The subject, which is the canonical and flat form:
        //   system:serviceaccount:<namespace>:<name>
        // Every projected token carries it, so there is no need to reach into the nested
        // kubernetes.io claim -- and reaching into it without a JSON parser would be a fragile
        // extraction for no extra information.
        String sub = Sealed.jsonString(json, "sub");
        if (sub != null) {
            String[] bits = sub.split(":");
            if (bits.length == 4 && bits[0].equals("system")) {
                return bits[3];
            }
        }
        return null;
    }
}
