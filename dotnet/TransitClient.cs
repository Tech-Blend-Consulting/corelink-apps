using System.Net;
using System.Text;
using System.Text.Json;
// Timer comes from here. It was used without this and compiled only where
// implicit usings happened to cover it.
using System.Threading;

/// <summary>
/// Transit API client for Tech Blend Secrets Management.
///
/// Authentication is via NHI (Non-Human Identity) passwordless attestation.
/// Construct with the transit URL, platform URL, and NHI identity ID, then
/// call NHIConnectAsync() (or NHIConnect()) before making any secret requests.
/// A background timer renews the session every 50 minutes automatically.
///
/// Requires .NET 6+. No external dependencies.
///
/// Usage:
///   using var client = new TransitClient("http://127.0.0.1:9090", "https://platform.example.com", "nhi_...");
///   await client.NHIConnectAsync();
///   var dbPass = await client.GetSecretAsync("DB_PASSWORD");
/// </summary>
public class TransitClient : IDisposable
{
    private readonly string _url;
    private readonly string _platformUrl;
    private readonly string _nhiId;
    private readonly HttpClient _httpClient;
    private readonly object _tokenLock = new();
    private string? _sessionId;
    private Timer? _heartbeatTimer;

    /// <summary>
    /// Construct a TransitClient for NHI passwordless authentication.
    /// Call NHIConnectAsync() before making secret requests.
    /// </summary>
    public TransitClient(string transitUrl, string platformUrl, string nhiId)
        : this(transitUrl, platformUrl, nhiId, null) { }

    /// <summary>
    /// As above, with an attestation supplied by the caller instead of detected.
    ///
    /// For a workload that runs nowhere the SDK can recognise -- a product with no connector, no
    /// pod and no instance identity document -- and federates to its own OIDC issuer instead.
    /// Return ("oidc", token).
    ///
    /// A delegate rather than a string, because these tokens are short lived by design: it is
    /// called on every connect and reconnect, so a session that drops at three in the morning
    /// re-mints rather than replaying something that expired hours ago.
    ///
    /// Nothing it returns authorises anything: CoreLink verifies the token against the issuer
    /// pinned to this identity, and the grant decides what the identity may do.
    /// </summary>
    public TransitClient(string transitUrl, string platformUrl, string nhiId,
        Func<(string type, string evidence)>? attest)
    {
        _url = transitUrl.TrimEnd('/');
        _platformUrl = platformUrl.TrimEnd('/');
        _nhiId = nhiId;
        _attest = attest;
        _httpClient = new HttpClient { Timeout = TimeSpan.FromSeconds(5) };
    }

    private readonly Func<(string type, string evidence)>? _attest;

    /// <summary>
    /// Connect to the platform using the NHI fingerprint.
    /// Must be called before making secret requests.
    /// Starts a background heartbeat on success.
    /// </summary>
    public async Task NHIConnectAsync()
    {
        // evidence must not be logged -- it may contain a Kubernetes SA token.
        var (attestType, evidence) = CollectAttestation();
        var payload = JsonSerializer.Serialize(new {
            nhi_id = _nhiId,
            attestation = new { type = attestType, evidence }
        });
        var content = new StringContent(payload, Encoding.UTF8, "application/json");
        var resp = await _httpClient.PostAsync(_platformUrl + "/api/v1/nhi-agent/connect", content);
        if (resp.StatusCode == HttpStatusCode.Forbidden)
            throw new Exception("NHI identity verification failed");
        resp.EnsureSuccessStatusCode();
        var body = await resp.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(body);
        var sid = doc.RootElement.GetProperty("session_id").GetString();

        // Treat a missing status field as "active" for backward compatibility.
        var status = doc.RootElement.TryGetProperty("status", out var statusProp)
            ? statusProp.GetString()
            : null;
        if (string.IsNullOrEmpty(status)) status = "active";

        if (status == "pending_approval")
        {
            var prefix = !string.IsNullOrEmpty(sid) && sid.Length > 8 ? sid[..8] : sid;
            Console.WriteLine($"Waiting for admin approval (session: {prefix})...");
            await PollApprovalAsync(sid!);
        }
        else if (status != "active")
        {
            throw new Exception($"NHI connect returned unexpected status: {status}");
        }

        lock (_tokenLock) { _sessionId = sid; }
        ScheduleHeartbeat();
    }

    /// <summary>
    /// Poll the platform every 5 seconds until the session is approved or rejected.
    /// Times out after 5 minutes (60 attempts).
    /// </summary>
    private async Task PollApprovalAsync(string sessionId)
    {
        var url = _platformUrl + "/api/v1/nhi-agent/connect/" + sessionId + "/status";
        for (int i = 0; i < 60; i++)
        {
            await Task.Delay(TimeSpan.FromSeconds(5));
            try
            {
                var resp = await _httpClient.GetAsync(url);
                if (resp.IsSuccessStatusCode)
                {
                    var body = await resp.Content.ReadAsStringAsync();
                    using var doc = JsonDocument.Parse(body);
                    if (doc.RootElement.TryGetProperty("status", out var s))
                    {
                        var status = s.GetString();
                        if (status == "active") return;
                        if (status == "rejected") throw new Exception("Connect request rejected by admin");
                    }
                }
            }
            catch (Exception e) when (e.Message == "Connect request rejected by admin")
            {
                throw;
            }
            catch
            {
                // transient error; keep polling
            }
        }
        throw new Exception("Approval timeout (5 minutes)");
    }

    /// <summary>Synchronous wrapper for NHIConnectAsync.</summary>
    public void NHIConnect() => NHIConnectAsync().GetAwaiter().GetResult();

    /// <summary>
    /// The secrets available to this client.
    ///
    /// A connector serves envelopes by name and offers no way to enumerate them: an application
    /// asks for what it was configured to ask for. There is nothing to list, so this throws rather
    /// than returning an empty list that would read as "no secrets".
    /// </summary>
    public Task<List<SecretEntry>> ListSecretsAsync() =>
        throw new NotSupportedException(
            "a connector serves envelopes by name and offers no listing; "
            + "name the secrets this application needs");

    /// <summary>Synchronous wrapper for ListSecretsAsync.</summary>
    public List<SecretEntry> ListSecrets() => ListSecretsAsync().GetAwaiter().GetResult();

    /// <summary>
    /// The value of a single secret by name.
    ///
    /// Takes the sealed envelope from the connector, asks CoreLink for the key to that secret, and
    /// opens it here. The connector cannot read what it served and CoreLink never sees the
    /// plaintext, so the value exists in this process and nowhere else.
    ///
    /// It used to ask the connector for plaintext. That endpoint answers 410 now, and this goes the
    /// sealed way instead, so an application already calling GetSecretAsync needs no change.
    /// </summary>
    public Task<string> GetSecretAsync(string name) => GetSecretSealedAsync(name);

    /// <summary>Synchronous wrapper for GetSecretAsync.</summary>
    public string GetSecret(string name) => GetSecretAsync(name).GetAwaiter().GetResult();

    /// <summary>
    /// Open a secret from a sealed envelope. See GetSecretAsync.
    ///
    /// Requires secrets:unwrap on the secret, and a connector granted secrets:cache on it.
    ///
    /// A stale envelope is retried once with the connector told to refetch, which is the case this
    /// exists for: the connector holding a version CoreLink has since rotated past. A second
    /// failure of the same kind is reported as stale rather than retried forever.
    /// </summary>
    public async Task<string> GetSecretSealedAsync(string name)
    {
        if (string.IsNullOrEmpty(_url))
            throw new InvalidOperationException("GetSecretSealedAsync needs a connector; set the transit URL");
        if (string.IsNullOrEmpty(_platformUrl) || string.IsNullOrEmpty(_nhiId))
            throw new InvalidOperationException("GetSecretSealedAsync needs an identity; set the platform URL and NHI id");

        try
        {
            return await OpenSealedAsync(name, false);
        }
        catch (Sealed.StaleEnvelopeException)
        {
            return await OpenSealedAsync(name, true);
        }
    }

    /// <summary>Synchronous wrapper for GetSecretSealedAsync.</summary>
    public string GetSecretSealed(string name) => GetSecretSealedAsync(name).GetAwaiter().GetResult();

    /// <summary>
    /// Sets the session directly, for tests.
    ///
    /// The sealed path needs a session and attestation is not what it is testing. Internal rather
    /// than public, so an application cannot reach past Connect. This project compiles its test
    /// alongside the SDK, so internal is visible to it and to nothing an application links.
    /// </summary>
    internal void SetSessionForTesting(string session)
    {
        lock (_tokenLock) { _sessionId = session; }
    }

    /// <summary>
    /// A TLS bundle, fetched through the sealed path and parsed here.
    ///
    /// A certificate is a secret whose value is a bundle, so it needs no delivery mechanism of its
    /// own: the same envelope, the same key, the same binding. The connector used to serve a
    /// bundle's parts from plaintext it held in memory, which was the last readable thing in that
    /// process.
    ///
    /// The private key exists in this process and nowhere else.
    /// </summary>
    public async Task<Sealed.Certificate> GetCertificateAsync(string name) =>
        Sealed.CertificateFrom(await GetSecretSealedAsync(name));

    /// <summary>Synchronous wrapper for GetCertificateAsync.</summary>
    public Sealed.Certificate GetCertificate(string name) =>
        GetCertificateAsync(name).GetAwaiter().GetResult();

    /// <summary>
    /// Ask CoreLink for a credential leased for a while.
    ///
    /// resourceType is one of Leases.ResourceSecret, ResourceDatabase or ResourceCloud. A zero TTL
    /// takes CoreLink's default; asking for longer than policy allows is CoreLink's decision, and
    /// the lease says what was actually granted.
    /// </summary>
    public async Task<Leases.Lease> RequestCredentialAsync(string resourceType, string resourceId, int ttlSeconds = 0)
    {
        if (string.IsNullOrEmpty(_platformUrl) || string.IsNullOrEmpty(_nhiId))
            throw new InvalidOperationException("RequestCredentialAsync needs an identity; set the platform URL and NHI id");
        if (Array.IndexOf(Leases.ResourceTypes, resourceType) < 0)
            throw new ArgumentException($"resource type {resourceType} is not one of {string.Join(", ", Leases.ResourceTypes)}", nameof(resourceType));
        if (string.IsNullOrEmpty(resourceId))
            throw new ArgumentException("a resource id is required", nameof(resourceId));

        var body = new Dictionary<string, object> { ["resource_type"] = resourceType, ["resource_id"] = resourceId };
        if (ttlSeconds > 0) body["ttl_seconds"] = ttlSeconds;

        var resp = await PlatformRequestAsync(HttpMethod.Post, "/api/v1/nhi-agent/credentials", body);
        if (resp.StatusCode != HttpStatusCode.OK)
            throw new Exception($"CoreLink refused to issue a credential: HTTP {(int)resp.StatusCode}");

        using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        var lease = Leases.FromElement(doc.RootElement);
        if (string.IsNullOrEmpty(lease.Id))
            throw new Exception("CoreLink issued a credential with no lease id");
        return lease;
    }

    /// <summary>
    /// Extend a lease, or say why it will not extend.
    ///
    /// Throws LeaseExhaustedException at the credential's maximum lifetime. That is not a failure to
    /// retry: request a new credential.
    /// </summary>
    public async Task RenewLeaseAsync(string leaseId)
    {
        if (string.IsNullOrEmpty(leaseId))
            throw new ArgumentException("a lease id is required", nameof(leaseId));

        var resp = await PlatformRequestAsync(
            HttpMethod.Post, $"/api/v1/nhi-agent/leases/{Uri.EscapeDataString(leaseId)}/renew", null);
        switch (resp.StatusCode)
        {
            case HttpStatusCode.OK:
                return;
            case HttpStatusCode.UnprocessableEntity:
                throw new Leases.LeaseExhaustedException("this credential cannot be extended further");
            case HttpStatusCode.NotFound:
                throw new Leases.LeaseNotFoundException("lease not found");
            default:
                throw new Exception($"renewing the lease failed: HTTP {(int)resp.StatusCode}");
        }
    }

    /// <summary>
    /// Hand a credential back before it expires.
    ///
    /// Worth doing rather than letting it lapse: it stops working at once. A lease already gone is
    /// not an error, because the caller's intent is satisfied either way.
    /// </summary>
    public async Task ReleaseCredentialAsync(string leaseId)
    {
        if (string.IsNullOrEmpty(leaseId))
            throw new ArgumentException("a lease id is required", nameof(leaseId));

        var resp = await PlatformRequestAsync(
            HttpMethod.Delete, $"/api/v1/nhi-agent/credentials/{Uri.EscapeDataString(leaseId)}", null);
        if (resp.StatusCode is HttpStatusCode.OK or HttpStatusCode.NoContent or HttpStatusCode.NotFound)
            return;
        throw new Exception($"releasing the credential failed: HTTP {(int)resp.StatusCode}");
    }

    /// <summary>
    /// The identity's active leases, without their credentials.
    ///
    /// The material is handed over once, at issue.
    /// </summary>
    public async Task<List<Leases.Lease>> ListLeasesAsync()
    {
        var resp = await PlatformRequestAsync(HttpMethod.Get, "/api/v1/nhi-agent/credentials", null);
        if (resp.StatusCode != HttpStatusCode.OK)
            throw new Exception($"listing leases failed: HTTP {(int)resp.StatusCode}");

        var result = new List<Leases.Lease>();
        using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        // "data" is the key CoreLink sends.
        if (doc.RootElement.TryGetProperty("data", out var rows) && rows.ValueKind == JsonValueKind.Array)
        {
            foreach (var row in rows.EnumerateArray())
            {
                result.Add(Leases.FromElement(row));
            }
        }
        return result;
    }

    /// <summary>Send an authenticated request to CoreLink.</summary>
    private async Task<HttpResponseMessage> PlatformRequestAsync(HttpMethod method, string path, object? body)
    {
        string? session;
        lock (_tokenLock) { session = _sessionId; }
        if (string.IsNullOrEmpty(session))
            throw new InvalidOperationException("no CoreLink session; connect first");

        var req = new HttpRequestMessage(method, _platformUrl + path);
        req.Headers.Add("X-NHI-Session", session);
        if (body is not null)
        {
            req.Content = new StringContent(JsonSerializer.Serialize(body), Encoding.UTF8, "application/json");
        }
        return await _httpClient.SendAsync(req);
    }

    /// <summary>One attempt at fetching, unwrapping and opening.</summary>
    private async Task<string> OpenSealedAsync(string name, bool refresh)
    {
        var envelopeUrl = _url + "/v1/envelopes/" + Sealed.EnvelopePath(name);
        if (refresh) envelopeUrl += "?refresh=1";

        // Unauthenticated: the connector has nothing to decide, because what it serves cannot be
        // opened without a grant CoreLink checks.
        var resp = await _httpClient.GetAsync(envelopeUrl);
        if (resp.StatusCode != HttpStatusCode.OK)
            throw new Exception($"the connector has no envelope for {name}: HTTP {(int)resp.StatusCode}");

        var body = await resp.Content.ReadAsStringAsync();
        string secretId, envelope;
        int servedVersion;
        using (var doc = JsonDocument.Parse(body))
        {
            secretId = doc.RootElement.TryGetProperty("secret_id", out var s) ? s.GetString() ?? "" : "";
            envelope = doc.RootElement.TryGetProperty("envelope", out var e) ? e.GetString() ?? "" : "";
            servedVersion = doc.RootElement.TryGetProperty("version", out var v) ? v.GetInt32() : -1;
        }
        if (string.IsNullOrEmpty(secretId) || string.IsNullOrEmpty(envelope))
            throw new Exception($"the connector served an incomplete envelope for {name}");

        var (dek, keyVersion, authoritativeName) = await UnwrapDekAsync(secretId);
        try
        {
            // The name CoreLink says this id belongs to must be the name that was asked for. See
            // Sealed.WrongSecretException: the AAD binds an envelope to its own id and version, so
            // a substituted secret opens cleanly and only this comparison catches it.
            var asked = name.Trim('/');
            if (!string.IsNullOrEmpty(authoritativeName) && authoritativeName != asked)
            {
                throw new Sealed.WrongSecretException(
                    $"asked for {asked} and the connector answered with {authoritativeName}");
            }

            // The key belongs to whatever version CoreLink currently holds. A different one means
            // this envelope is behind, and saying so is clearer than letting the AEAD fail for an
            // unexplained reason.
            if (keyVersion != servedVersion)
            {
                throw new Sealed.StaleEnvelopeException(
                    $"the connector served version {servedVersion}, CoreLink is on {keyVersion}");
            }

            var plaintext = Sealed.OpenEnvelope(envelope, dek, secretId, keyVersion);
            try
            {
                return Sealed.ValueFrom(plaintext);
            }
            finally
            {
                Array.Clear(plaintext, 0, plaintext.Length);
            }
        }
        finally
        {
            Array.Clear(dek, 0, dek.Length);
        }
    }

    /// <summary>
    /// Ask CoreLink for the key to one secret.
    ///
    /// CoreLink unwraps its own copy, so nothing this process holds takes part: an application
    /// handed somebody else's ciphertext cannot have it opened by naming a secret it is entitled
    /// to.
    /// </summary>
    private async Task<(byte[] Dek, int Version, string Name)> UnwrapDekAsync(string secretId)
    {
        string? session;
        lock (_tokenLock) { session = _sessionId; }
        if (string.IsNullOrEmpty(session))
            throw new InvalidOperationException("no CoreLink session; connect first");

        var req = new HttpRequestMessage(
            HttpMethod.Post,
            _platformUrl + "/api/v1/nhi-agent/secrets/" + Uri.EscapeDataString(secretId) + "/unwrap");
        req.Headers.Add("X-NHI-Session", session);

        var resp = await _httpClient.SendAsync(req);
        if (resp.StatusCode != HttpStatusCode.OK)
            throw new Exception($"CoreLink refused to unwrap: HTTP {(int)resp.StatusCode}");

        var body = await resp.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(body);
        var dekB64 = doc.RootElement.TryGetProperty("dek", out var d) ? d.GetString() ?? "" : "";
        var version = doc.RootElement.TryGetProperty("version", out var v) ? v.GetInt32() : -1;
        // The name is CoreLink's answer to "which secret is this id?", which only it can give.
        // The caller compares it against what it asked for.
        var name = doc.RootElement.TryGetProperty("name", out var n) ? n.GetString() ?? "" : "";
        if (string.IsNullOrEmpty(dekB64))
            throw new Exception("CoreLink returned no key");

        return (Convert.FromBase64String(dekB64), version, name);
    }

    /// <summary>
    /// Stop background timers and send a best-effort disconnect to invalidate the session.
    /// </summary>
    public void Dispose()
    {
        _heartbeatTimer?.Dispose();
        if (!string.IsNullOrEmpty(_nhiId) && !string.IsNullOrEmpty(_sessionId))
        {
            try
            {
                var req = new HttpRequestMessage(HttpMethod.Post, _platformUrl + "/api/v1/nhi-agent/disconnect");
                req.Headers.Add("X-NHI-Session", _sessionId);
                _httpClient.Send(req);
            }
            catch { }
        }
        _httpClient.Dispose();
    }

    // --- NHI internals ---

    /// <summary>
    /// Auto-detect the runtime environment and return the attestation type and evidence.
    ///
    /// Detection order:
    ///   1. Kubernetes: service account token projected by the kubelet.
    ///   2. Host fallback: stable fingerprint from ComputeFingerprint().
    ///
    /// AWS, Azure, and GCP detection require HTTP calls to instance metadata
    /// endpoints and are left as future work. The server accepts "host" for
    /// non-cloud deployments.
    ///
    /// The returned evidence must never be logged -- it may contain a
    /// Kubernetes service account JWT.
    /// </summary>
    private (string type, string evidence) CollectAttestation()
    {
        // The caller first: a workload federating to its own issuer knows how to get its token and
        // the SDK does not; a pod or a host is the other way round.
        if (_attest is not null)
        {
            return _attest();
        }
        return DetectAttestation();
    }

    private (string type, string evidence) DetectAttestation()
    {
        // Kubernetes: service account token projected by the kubelet.
        const string saPath = "/var/run/secrets/kubernetes.io/serviceaccount/token";
        if (File.Exists(saPath))
        {
            var token = File.ReadAllText(saPath).Trim();
            if (!string.IsNullOrEmpty(token)) return ("kubernetes", token);
        }

        // Host fallback: use the stable fingerprint as evidence.
        var (fp, _) = ComputeFingerprint();
        return ("host", fp);
    }

    /// <summary>
    /// Compute the NHI fingerprint and supporting metadata.
    /// The fingerprint is never logged by this method.
    /// </summary>
    private (string fingerprint, Dictionary<string, string> meta) ComputeFingerprint()
    {
        var meta = new Dictionary<string, string>();

        // Binary hash of the running executable
        var execPath = System.Diagnostics.Process.GetCurrentProcess().MainModule?.FileName ?? "";
        byte[] binHash;
        try
        {
            binHash = System.Security.Cryptography.SHA256.HashData(File.ReadAllBytes(execPath));
        }
        catch
        {
            // Fallback when the exe path is unavailable (e.g., single-file publish without native AOT)
            binHash = System.Security.Cryptography.SHA256.HashData(Encoding.UTF8.GetBytes(Environment.Version.ToString()));
        }
        meta["binary_hash"] = Convert.ToHexString(binHash).ToLower();

        // Machine ID: prefer /etc/machine-id on Linux, fall back to MachineName
        var machineId = Environment.MachineName;
        if (OperatingSystem.IsLinux())
        {
            try { machineId = File.ReadAllText("/etc/machine-id").Trim(); } catch { }
        }
        meta["machine_id"] = machineId;
        meta["hostname"] = Environment.MachineName;
        meta["os"] = Environment.OSVersion.Platform.ToString().ToLower();

        // Combine: SHA-256(binHash || machineId || hostname || nhiId)
        using var sha = System.Security.Cryptography.SHA256.Create();
        sha.TransformBlock(binHash, 0, binHash.Length, null, 0);
        var machBytes = Encoding.UTF8.GetBytes(machineId);
        sha.TransformBlock(machBytes, 0, machBytes.Length, null, 0);
        var hostBytes = Encoding.UTF8.GetBytes(Environment.MachineName);
        sha.TransformBlock(hostBytes, 0, hostBytes.Length, null, 0);
        var nhiBytes = Encoding.UTF8.GetBytes(_nhiId);
        sha.TransformFinalBlock(nhiBytes, 0, nhiBytes.Length);

        return (Convert.ToHexString(sha.Hash!).ToLower(), meta);
    }

    private void ScheduleHeartbeat()
    {
        _heartbeatTimer?.Dispose();
        _heartbeatTimer = new Timer(_ => NHIHeartbeatAsync().Wait(), null,
            TimeSpan.FromMinutes(50), TimeSpan.FromMinutes(50));
    }

    private async Task NHIHeartbeatAsync()
    {
        // evidence must not be logged -- it may contain a Kubernetes SA token.
        var (attestType, evidence) = CollectAttestation();
        var payload = JsonSerializer.Serialize(new {
            attestation = new { type = attestType, evidence }
        });
        var content = new StringContent(payload, Encoding.UTF8, "application/json");
        string? currentSession;
        lock (_tokenLock) { currentSession = _sessionId; }
        var req = new HttpRequestMessage(HttpMethod.Post, _platformUrl + "/api/v1/nhi-agent/heartbeat") { Content = content };
        req.Headers.Add("X-NHI-Session", currentSession);
        try
        {
            var resp = await _httpClient.SendAsync(req);
            if (resp.StatusCode == HttpStatusCode.Unauthorized || resp.StatusCode == HttpStatusCode.Forbidden)
                await NHIConnectAsync();
        }
        catch
        {
            try { await NHIConnectAsync(); } catch { }
        }
    }

    // --- Auth / HTTP helpers ---

    private async Task<HttpResponseMessage> AuthedGetAsync(string url)
    {
        var resp = await DoGetAsync(url);
        if (resp.StatusCode == HttpStatusCode.Unauthorized)
        {
            // Session expired: reconnect and retry once.
            await NHIConnectAsync();
            resp = await DoGetAsync(url);
        }
        return resp;
    }

    private async Task<HttpResponseMessage> DoGetAsync(string url)
    {
        var req = new HttpRequestMessage(HttpMethod.Get, url);
        string? session;
        lock (_tokenLock) { session = _sessionId; }
        if (!string.IsNullOrEmpty(session))
            req.Headers.Add("X-NHI-Session", session);
        return await _httpClient.SendAsync(req);
    }

    public record SecretEntry(string Name, string Value);
}
