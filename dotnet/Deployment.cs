using System.Text;
using System.Text.Json;

/// <summary>
/// The deployment file: what an application was configured to ask for.
///
/// <code>
/// nhiId:          11111111-2222-3333-4444-555555555555
/// serviceAccount: orders
/// secrets:
///   - production/dbone
///   - production/apikey
/// </code>
///
/// It tells the SDK which identity to attest as and which secrets to ask for. That is all it is.
///
/// **Nothing in it grants anything**, and that must stay true even when somebody proposes
/// provisioning grants from it as a convenience. Anyone who can edit a Deployment can add a path to
/// this file; if that provisioned access, "edit deployments" would quietly become "read any
/// secret". The file is a request. The grant on the NHI is the only answer, and CoreLink checks it
/// on every call regardless of what is written here.
///
/// Neither value is sensitive. The NHI id is a pointer, not a credential: Connect looks the
/// identity up by the id presented and then verifies the evidence against *that identity's*
/// binding, so naming someone else's id and attesting with your own ServiceAccount fails the claim
/// match.
///
/// **Deliberately not a YAML parser.** YAML is a large language -- anchors, flow collections,
/// multi-line scalars, implicit typing -- and most of it is ways for a file to mean something other
/// than it appears to. Three keys are needed, so everything else is refused rather than guessed at,
/// and the six SDKs then agree with each other rather than each agreeing with whatever YAML library
/// its language happened to ship.
///
/// Pinned against the other five SDKs by sdk/testdata/deployment_cases.json.
/// </summary>
public sealed class Deployment
{
    /// <summary>Where the file is looked for when no path is given.</summary>
    public const string DefaultPath = "/etc/corelink/secrets.yaml";

    /// <summary>Environment variable that overrides the default path.</summary>
    public const string PathEnv = "CORELINK_DEPLOYMENT_FILE";

    private const string SaTokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token";

    /// <summary>A deployment file that could not be read as written.</summary>
    public class DeploymentException : Exception
    {
        public DeploymentException(string message) : base(message) { }
    }

    public string NhiId { get; private set; } = "";
    public string ServiceAccount { get; private set; } = "";
    public List<string> Secrets { get; } = new();
    public string Path { get; private set; } = "";

    private Deployment() { }

    /// <summary>Read the deployment file, throwing if it is missing or unreadable.</summary>
    public static Deployment Load(string? p = null)
    {
        var file = ResolvePath(p);
        string text;
        try
        {
            text = File.ReadAllText(file);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            throw new DeploymentException($"reading the deployment file {file}: {e.Message}");
        }

        Deployment d;
        try
        {
            d = Parse(text);
        }
        catch (DeploymentException e)
        {
            throw new DeploymentException($"{file}: {e.Message}");
        }
        d.Path = file;

        if (d.NhiId.Length == 0)
        {
            throw new DeploymentException($"{file}: nhiId is required; it names the identity to attest as");
        }
        if (d.Secrets.Count == 0)
        {
            throw new DeploymentException(
                $"{file}: secrets is required; an application asks for what it was configured to " +
                "ask for rather than discovering what exists");
        }
        return d;
    }

    /// <summary>
    /// Load, except that a missing file returns null.
    ///
    /// A file that exists and does not parse is still an error: the difference that matters is "no
    /// file" against "a file I could not read", and silently ignoring the second would run the
    /// application on a configuration nobody wrote.
    /// </summary>
    public static Deployment? LoadIfPresent(string? p = null)
    {
        var file = ResolvePath(p);
        if (!File.Exists(file)) return null;
        return Load(file);
    }

    private static string ResolvePath(string? p)
    {
        if (!string.IsNullOrEmpty(p)) return p!;
        var env = Environment.GetEnvironmentVariable(PathEnv);
        return string.IsNullOrEmpty(env) ? DefaultPath : env!;
    }

    /// <summary>Read the one shape this file has, and refuse the rest.</summary>
    public static Deployment Parse(string text)
    {
        var d = new Deployment();
        var seen = new HashSet<string>();
        string? listKey = null;

        var lines = text.Split('\n');
        for (var i = 0; i < lines.Length; i++)
        {
            var raw = lines[i];
            var n = i + 1;

            if (raw.Contains('\t'))
            {
                throw new DeploymentException($"line {n}: tabs are not allowed in indentation");
            }

            // A comment is only a comment at the start of a line here. Stripping a trailing "#"
            // would corrupt any value that legitimately contains one.
            var trimmed = raw.Trim();
            if (trimmed.Length == 0 || trimmed.StartsWith('#')) continue;
            if (trimmed.StartsWith("---") || trimmed.StartsWith("..."))
            {
                throw new DeploymentException($"line {n}: multiple documents are not supported");
            }
            if (trimmed.Contains('&') || trimmed.Contains('*'))
            {
                throw new DeploymentException($"line {n}: anchors and aliases are not supported");
            }

            // A list entry, which belongs to the key above it.
            if (trimmed.StartsWith("- ") || trimmed == "-")
            {
                if (listKey is null)
                {
                    throw new DeploymentException($"line {n}: a list entry with no key above it");
                }
                var item = Scalar(trimmed.Substring(1).Trim(), n);
                if (item.Length == 0)
                {
                    throw new DeploymentException($"line {n}: an empty list entry");
                }
                if (listKey != "secrets")
                {
                    throw new DeploymentException($"line {n}: {listKey} does not take a list");
                }
                d.Secrets.Add(item);
                continue;
            }

            // Anything else must be a key at the left margin. Leading whitespace is what makes it
            // indented; trailing whitespace is invisible and harmless.
            if (raw.StartsWith(' '))
            {
                throw new DeploymentException(
                    $"line {n}: unexpected indentation; this file is a flat set of keys");
            }
            var colon = trimmed.IndexOf(':');
            if (colon < 0) throw new DeploymentException($"line {n}: expected \"key: value\"");
            var key = trimmed.Substring(0, colon);
            var value = trimmed.Substring(colon + 1);
            // YAML needs a space after the colon to make this a mapping at all -- "nhiId:abc" is a
            // plain scalar, not a key.
            if (value.Length > 0 && !value.StartsWith(' '))
            {
                throw new DeploymentException($"line {n}: a key needs a space after its colon");
            }
            key = key.Trim();
            value = value.Trim();

            if (!seen.Add(key))
            {
                // Two values for one key: a reader has to pick, and either choice is somebody's
                // surprise.
                throw new DeploymentException($"line {n}: {key} appears more than once");
            }
            listKey = null;

            switch (key)
            {
                case "nhiId":
                case "nhiID":
                case "nhi_id":
                    d.NhiId = Scalar(value, n);
                    break;
                case "serviceAccount":
                case "service_account":
                    d.ServiceAccount = Scalar(value, n);
                    break;
                case "secrets":
                    if (value.Length == 0)
                    {
                        // The list form; entries follow on their own lines.
                        listKey = "secrets";
                        continue;
                    }
                    d.Secrets.Add(Scalar(value, n));
                    break;
                default:
                    // Refused rather than ignored. A typo in a key an application relies on would
                    // otherwise be silence, and the application would run asking for nothing.
                    throw new DeploymentException($"line {n}: unknown key {key}");
            }
        }

        return d;
    }

    /// <summary>Read one plain value, refusing the YAML forms this does not implement.</summary>
    private static string Scalar(string v, int n)
    {
        if (v.Length == 0) return "";
        if (v.StartsWith('[') || v.StartsWith('{'))
        {
            throw new DeploymentException(
                $"line {n}: flow collections are not supported; use a \"- item\" list");
        }
        if (v.StartsWith('|') || v.StartsWith('>'))
        {
            throw new DeploymentException($"line {n}: multi-line scalars are not supported");
        }
        if (v.Length >= 2)
        {
            var first = v[0];
            var last = v[^1];
            if ((first == '"' && last == '"') || (first == '\'' && last == '\''))
            {
                var inner = v.Substring(1, v.Length - 2);
                if (inner.Contains(first))
                {
                    throw new DeploymentException(
                        $"line {n}: escapes inside a quoted value are not supported");
                }
                return inner;
            }
            if (first is '"' or '\'')
            {
                throw new DeploymentException($"line {n}: a quoted value is not closed");
            }
        }
        else if (v is "\"" or "'")
        {
            throw new DeploymentException($"line {n}: a quoted value is not closed");
        }
        if (v.Contains(": ") || v.EndsWith(':'))
        {
            // YAML refuses ": " inside a plain scalar because it cannot tell the value from a
            // nested mapping.
            throw new DeploymentException($"line {n}: a value containing a colon must be quoted");
        }
        if (v.Contains('#'))
        {
            // Ambiguous: YAML would read " #" as a trailing comment, and a reader that guesses
            // either way is wrong for somebody.
            throw new DeploymentException($"line {n}: a value containing # must be quoted");
        }
        return v;
    }

    /// <summary>
    /// Throw if the pod is not running as the ServiceAccount the file names.
    ///
    /// **A misconfiguration check, not a security control.** The projected token's claims are read
    /// without verifying its signature, because nothing this concludes is trusted: CoreLink
    /// verifies that token properly, against the identity's own binding, and that is what decides
    /// whether the workload is who it says. Re-deciding it here would be a second authorization
    /// path for one question.
    ///
    /// No name, no token, or an unreadable one: no opinion, no error.
    /// </summary>
    public void VerifyServiceAccount()
    {
        if (ServiceAccount.Length == 0) return;
        string token;
        try
        {
            token = File.ReadAllText(SaTokenPath);
        }
        catch
        {
            return;
        }
        var actual = ServiceAccountFromToken(token);
        if (actual is null || actual == ServiceAccount) return;
        throw new DeploymentException(
            $"{Path} names serviceAccount {ServiceAccount} but this pod is running as {actual}; " +
            "the deployment file and the pod spec disagree");
    }

    /// <summary>
    /// The ServiceAccount name from a projected token, or null. The signature is not checked; see
    /// <see cref="VerifyServiceAccount"/>.
    /// </summary>
    public static string? ServiceAccountFromToken(string token)
    {
        var parts = token.Trim().Split('.');
        if (parts.Length != 3) return null;

        var payload = parts[1].Replace('-', '+').Replace('_', '/');
        payload = payload.PadRight(payload.Length + ((4 - payload.Length % 4) % 4), '=');
        string json;
        try
        {
            json = Encoding.UTF8.GetString(Convert.FromBase64String(payload));
        }
        catch (FormatException)
        {
            return null;
        }

        try
        {
            using var doc = JsonDocument.Parse(json);
            // The subject, which is the canonical and flat form:
            //   system:serviceaccount:<namespace>:<name>
            // Every projected token carries it, so there is no need to reach into the nested
            // kubernetes.io claim for the same name.
            if (!doc.RootElement.TryGetProperty("sub", out var sub)) return null;
            var bits = (sub.GetString() ?? "").Split(':');
            if (bits.Length == 4 && bits[0] == "system") return bits[3];
        }
        catch (JsonException)
        {
            return null;
        }
        return null;
    }
}
