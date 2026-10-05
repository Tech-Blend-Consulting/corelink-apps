using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;

/// <summary>
/// The sealed envelope, opened against a fixture the platform produced.
///
/// The fixture comes from internal/crypto, which is what CoreLink stores and what the unwrap
/// endpoint returns, so this checks agreement with the platform rather than agreement with itself.
///
/// Regenerate the fixture: go test ./internal/crypto/ -run TestSDKFixture -update
///
/// Run: cd sdk/dotnet &amp;&amp; dotnet run
///
/// Plain Main rather than a test framework, because this SDK is a single dependency-free file and
/// a framework would be the only dependency in the tree.
/// </summary>
public static class SealedTest
{
    private static int _failures;

    public static int Main()
    {
        var json = File.ReadAllText(Path.Combine("..", "testdata", "sealed_envelope.json"));
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        var secretId = root.GetProperty("secret_id").GetString()!;
        var version = root.GetProperty("version").GetInt32();
        var envelope = root.GetProperty("envelope").GetString()!;
        var dek = Convert.FromBase64String(root.GetProperty("dek").GetString()!);
        var aad = Convert.FromBase64String(root.GetProperty("aad").GetString()!);
        var expectedPlaintext = root.GetProperty("expected_plaintext").GetString()!;
        var expectedValue = root.GetProperty("expected_value").GetString()!;

        // One wire format shared with crypto.SecretAAD. If this drifts, nothing opens, so it is
        // checked against bytes the platform wrote.
        Check("the AAD matches the platform's",
            Sealed.SecretAad(secretId, version).AsSpan().SequenceEqual(aad));

        var plaintext = Sealed.OpenEnvelope(envelope, dek, secretId, version);
        Check("it opens what the platform sealed",
            Encoding.UTF8.GetString(plaintext) == expectedPlaintext);
        Check("the value comes out of the record", Sealed.ValueFrom(plaintext) == expectedValue);

        // What makes a stale cached envelope fail closed rather than being served as though it were
        // current.
        Check("the wrong version does not open it",
            ThrowsStale(() => Sealed.OpenEnvelope(envelope, dek, secretId, version + 1)));

        // The case authorization cannot catch: the caller may hold unwrap on both secrets, so only
        // the binding can stop this.
        Check("a false secret id does not open it",
            ThrowsStale(() => Sealed.OpenEnvelope(
                envelope, dek, "00000000-0000-0000-0000-000000000000", version)));

        Check("another key does not open it",
            ThrowsCorrupt(() => Sealed.OpenEnvelope(envelope, new byte[32], secretId, version)));

        // Refetching cannot repair altered ciphertext, so it must not be reported as something a
        // refetch would fix.
        Check("altered ciphertext is corrupt, not stale",
            ThrowsCorrupt(() => Sealed.OpenEnvelope(Alter(envelope), dek, secretId, version)));

        Check("EnvelopePath keeps slashes",
            Sealed.EnvelopePath("production/dbone") == "production/dbone"
            && Sealed.EnvelopePath("/production/dbone/") == "production/dbone"
            && Sealed.EnvelopePath("prod/db one") == "prod/db%20one");

        var dotsRefused = true;
        foreach (var bad in new[] { "prod/../etc/passwd", "prod/.", "..", "prod//dbone", "", "/" })
        {
            var refused = false;
            try { Sealed.EnvelopePath(bad); }
            catch (ArgumentException) { refused = true; }
            if (!refused)
            {
                Console.WriteLine($"  {bad} was not refused");
                dotsRefused = false;
            }
        }
        Check("EnvelopePath refuses dot segments", dotsRefused);

        // A certificate comes back one level deeper than a password: the stored record wraps the
        // value, and for a certificate the value is itself JSON. An SDK that returned the record
        // rather than its value would look correct on a password and produce an empty certificate
        // here, so this runs the whole local chain against a bundle the platform sealed.
        var certJson = File.ReadAllText(Path.Combine("..", "testdata", "sealed_certificate.json"));
        using var certDoc = JsonDocument.Parse(certJson);
        var certRoot = certDoc.RootElement;

        var certEnvelope = certRoot.GetProperty("envelope").GetString()!;
        var certDek = Convert.FromBase64String(certRoot.GetProperty("dek").GetString()!);
        var certSecretId = certRoot.GetProperty("secret_id").GetString()!;
        var certVersion = certRoot.GetProperty("version").GetInt32();
        var certExpectedValue = certRoot.GetProperty("expected_value").GetString()!;

        var certPlaintext = Sealed.OpenEnvelope(certEnvelope, certDek, certSecretId, certVersion);
        var certValue = Sealed.ValueFrom(certPlaintext);
        Check("the certificate chain produces the sealed bundle", certValue == certExpectedValue);

        var bundle = Sealed.CertificateFrom(certValue);
        Check("the bundle's parts come out",
            bundle.CertificatePem.Contains("BEGIN CERTIFICATE")
            && bundle.PrivateKeyPem.Contains("BEGIN PRIVATE KEY")
            && bundle.CaChainPem.Contains("BEGIN CERTIFICATE"));

        Check("ToString does not carry the key",
            !new Sealed.Certificate("cert-pem", "super-secret-key", "").ToString()
                .Contains("super-secret-key"));

        var nonBundlesRefused = true;
        foreach (var bad in new[]
                 {
                     "{\"value\":\"a-password\"}", "a-bare-password", "{}",
                     "{\"certificate\":\"c\"}", "{\"private_key\":\"k\"}", "[]"
                 })
        {
            var refused = false;
            try { Sealed.CertificateFrom(bad); }
            catch (ArgumentException) { refused = true; }
            if (!refused)
            {
                Console.WriteLine($"  {bad} was not refused as a bundle");
                nonBundlesRefused = false;
            }
        }
        Check("a secret that is not a bundle is refused", nonBundlesRefused);

        // The lease types, checked without a server: the lifecycle calls are plain
        // HTTP and what is worth pinning here is the redaction and the term
        // arithmetic, which is where a wrong implementation is silent.
        var leaseJson = JsonDocument.Parse(
            "{\"lease_id\":\"lease-1\",\"credential\":\"{\\\"username\\\":\\\"dyn_abc\\\"}\"," +
            "\"issued_at\":\"2026-10-04T12:00:00Z\",\"expires_at\":\"2026-10-04T12:15:00Z\"}");
        var lease = Leases.FromElement(leaseJson.RootElement);

        Check("a lease carries what renewal needs",
            lease.Id == "lease-1" && lease.Credential.Contains("dyn_abc")
            && lease.ExpiresAt is not null && lease.IssuedAt is not null);

        // A lease is logged while tracing its lifecycle; its rendering must not leak.
        Check("the lease rendering does not carry the credential",
            !lease.ToString().Contains("dyn_abc"));

        Check("the term comes from the lease's own timestamps",
            lease.Term(TimeSpan.FromMinutes(1)) == TimeSpan.FromMinutes(15));

        var noStamps = Leases.FromElement(JsonDocument.Parse("{\"id\":\"x\"}").RootElement);
        Check("the term falls back when the timestamps are absent",
            noStamps.Term(TimeSpan.FromMinutes(1)) == TimeSpan.FromMinutes(1));
        Check("remaining is zero without an expiry", noStamps.Remaining == TimeSpan.Zero);

        // A listing row carries no credential, because the material is handed over
        // once, at issue.
        var listingRow = Leases.FromElement(
            JsonDocument.Parse("{\"id\":\"lease-1\",\"expires_at\":\"2026-10-04T12:15:00Z\"}").RootElement);
        Check("a listing row has no credential", listingRow.Credential == "");

        // An envelope written before binding existed carries no AAD, and opens.
        //
        // Not a rollback -- the thing this must never be confused with. The platform skips its own
        // compare for these, so an SDK that insisted on the expected AAD would call every
        // pre-binding secret corrupt. All twenty of production's versions were unbound when this
        // was measured, so that SDK could not read a single real secret.
        var legacyJson = File.ReadAllText(Path.Combine("..", "testdata", "sealed_legacy_no_aad.json"));
        using var legacyDoc = JsonDocument.Parse(legacyJson);
        var legacyRoot = legacyDoc.RootElement;
        var legacyEnvelope = legacyRoot.GetProperty("envelope").GetString()!;
        var legacyDek = Convert.FromBase64String(legacyRoot.GetProperty("dek").GetString()!);
        var legacySecretId = legacyRoot.GetProperty("secret_id").GetString()!;
        var legacyVersion = legacyRoot.GetProperty("version").GetInt32();
        var legacyExpected = legacyRoot.GetProperty("expected_value").GetString()!;

        var legacyPlaintext =
            Sealed.OpenEnvelope(legacyEnvelope, legacyDek, legacySecretId, legacyVersion);
        Check("a pre-binding envelope opens and is not called corrupt",
            Sealed.ValueFrom(legacyPlaintext) == legacyExpected);

        // Unbound does not mean unchecked.
        Check("a pre-binding envelope still needs the right key",
            ThrowsCorrupt(() => Sealed.OpenEnvelope(
                legacyEnvelope, new byte[32], legacySecretId, legacyVersion)));

        // A connector answering with a different secret than the one asked for.
        //
        // The attack the AAD does not cover. The envelope served here is the real fixture, under
        // the wrong name: the key opens it, the version matches, the tag verifies. Every
        // cryptographic check passes, so the only thing that can catch it is comparing the name
        // CoreLink says the id belongs to against the name the application asked for.
        SubstitutionCases(secretId, version, envelope,
            Convert.ToBase64String(dek), expectedValue).GetAwaiter().GetResult();

        // The deployment file reader, against the cases every SDK shares.
        //
        // Six hand-written readers drift unless one thing pins them:
        // sdk/testdata/deployment_cases.json is that thing.
        DeploymentCases();

        if (_failures > 0)
        {
            Console.WriteLine($"{_failures} failed");
            return 1;
        }
        Console.WriteLine("all passed");
        return 0;
    }

    // The name the fixture's secret really has, and the name the application asks for. The
    // connector answers the second with the first.
    private const string RealName = "production/other-secret";
    private const string AskedName = "production/dbone";

    /// <summary>
    /// Drive the whole sealed path against one listener standing in for both the connector and
    /// CoreLink, so the name comparison is exercised where it actually lives.
    /// </summary>
    private static async Task SubstitutionCases(
        string secretId, int version, string envelope, string dekB64, string expectedValue)
    {
        // What the unwrap endpoint reports as the authoritative name; set per case.
        var authoritativeName = RealName;

        using var listener = new HttpListener();
        var port = FreePort();
        var baseUrl = $"http://127.0.0.1:{port}";
        listener.Prefixes.Add(baseUrl + "/");
        listener.Start();

        var serving = Task.Run(async () =>
        {
            while (listener.IsListening)
            {
                HttpListenerContext ctx;
                try { ctx = await listener.GetContextAsync(); }
                catch (HttpListenerException) { return; }
                catch (ObjectDisposedException) { return; }

                var path = ctx.Request.Url!.AbsolutePath;
                var payload = path.EndsWith("/unwrap")
                    // CoreLink: unwraps its own copy and says which name the id belongs to.
                    ? $"{{\"dek\":\"{dekB64}\",\"version\":{version},\"name\":\"{authoritativeName}\"}}"
                    // The connector: asked for one name, answers with the other secret's id and
                    // envelope. A real envelope, just not the requested one.
                    : $"{{\"secret_id\":\"{secretId}\",\"name\":\"{AskedName}\","
                      + $"\"version\":{version},\"envelope\":\"{envelope}\"}}";

                var bytes = Encoding.UTF8.GetBytes(payload);
                ctx.Response.ContentType = "application/json";
                ctx.Response.ContentLength64 = bytes.Length;
                await ctx.Response.OutputStream.WriteAsync(bytes);
                ctx.Response.Close();
            }
        });

        try
        {
            using var client = new TransitClient(baseUrl, baseUrl, "nhi-1");
            client.SetSessionForTesting("session-in-place");

            authoritativeName = RealName;
            var refused = false;
            try { await client.GetSecretSealedAsync(AskedName); }
            catch (Sealed.WrongSecretException e)
            {
                // The message has to name both, or an operator cannot tell which connector lied
                // about what.
                refused = e.Message.Contains(AskedName) && e.Message.Contains(RealName);
            }
            catch (Exception e) { Console.WriteLine($"  wanted WrongSecretException, got {e.GetType().Name}"); }
            Check("a substituted secret is refused", refused);

            // The same path with the names agreeing: proves the check refuses substitution rather
            // than refusing everything.
            authoritativeName = AskedName;
            Check("the right secret still opens",
                await client.GetSecretSealedAsync(AskedName) == expectedValue);

            // An older CoreLink that does not send the name yet. Refusing here would break every
            // application against it; the AAD still binds id and version.
            authoritativeName = "";
            Check("a platform sending no name is not refused",
                await client.GetSecretSealedAsync(AskedName) == expectedValue);
        }
        finally
        {
            listener.Stop();
            await serving;
        }
    }

    /// <summary>A port nothing is listening on, since HttpListener wants one up front.</summary>
    private static int FreePort()
    {
        var probe = new TcpListener(IPAddress.Loopback, 0);
        probe.Start();
        var port = ((IPEndPoint)probe.LocalEndpoint).Port;
        probe.Stop();
        return port;
    }


    /// <summary>Run the shared deployment cases: the accepted files and the refused ones.</summary>
    private static void DeploymentCases()
    {
        var casesJson = File.ReadAllText(Path.Combine("..", "testdata", "deployment_cases.json"));
        using var doc = JsonDocument.Parse(casesJson);
        var root = doc.RootElement;

        var accepted = root.GetProperty("accepted");
        var rejected = root.GetProperty("rejected");
        // The counts are the first check: a reader that quietly dropped cases would make every
        // assertion below pass by not running.
        Check("the fixture has accepted cases", accepted.GetArrayLength() >= 10);
        Check("the fixture has rejected cases", rejected.GetArrayLength() >= 20);

        var acceptedOk = true;
        foreach (var c in accepted.EnumerateArray())
        {
            var name = c.GetProperty("name").GetString() ?? "";
            Deployment d;
            try
            {
                d = LoadDeploymentText(c.GetProperty("text").GetString() ?? "");
            }
            catch (Exception e)
            {
                Console.WriteLine($"  accepted/{name}: refused a file the other SDKs accept: {e.Message}");
                acceptedOk = false;
                continue;
            }
            var wantSecrets = c.GetProperty("secrets").EnumerateArray()
                .Select(x => x.GetString() ?? "").ToList();
            if (d.NhiId != (c.GetProperty("nhiId").GetString() ?? "")
                || d.ServiceAccount != (c.GetProperty("serviceAccount").GetString() ?? "")
                || string.Join(",", d.Secrets) != string.Join(",", wantSecrets))
            {
                Console.WriteLine($"  accepted/{name}: parsed to something else");
                acceptedOk = false;
            }
        }
        Check("every accepted case parses to the shared result", acceptedOk);

        var rejectedOk = true;
        foreach (var c in rejected.EnumerateArray())
        {
            var name = c.GetProperty("name").GetString() ?? "";
            var refused = false;
            try
            {
                LoadDeploymentText(c.GetProperty("text").GetString() ?? "");
            }
            catch (Deployment.DeploymentException)
            {
                refused = true;
            }
            if (!refused)
            {
                Console.WriteLine($"  rejected/{name}: accepted a file the other SDKs refuse");
                rejectedOk = false;
            }
        }
        Check("every rejected case is refused", rejectedOk);

        // The ServiceAccount check only speaks when it can see a disagreement.
        var payload = Convert.ToBase64String(
            Encoding.UTF8.GetBytes("{\"sub\":\"system:serviceaccount:prod:billing\"}"))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');
        Check("it reads the name out of a projected token",
            Deployment.ServiceAccountFromToken($"x.{payload}.y") == "billing");
        Check("junk is no opinion", Deployment.ServiceAccountFromToken("not-a-token") is null);

        var missing = Path.Combine(Path.GetTempPath(), "corelink-absent-" + Guid.NewGuid());
        Check("a missing file is not an error for the optional loader",
            Deployment.LoadIfPresent(missing) is null);
    }

    /// <summary>Run the whole load, so the shared cases exercise what an application calls.</summary>
    private static Deployment LoadDeploymentText(string text)
    {
        var dir = Directory.CreateTempSubdirectory("deployment");
        try
        {
            var p = Path.Combine(dir.FullName, "secrets.yaml");
            File.WriteAllText(p, text);
            return Deployment.Load(p);
        }
        finally
        {
            dir.Delete(true);
        }
    }

    /// <summary>Flip a ciphertext bit, leaving the binding intact.</summary>
    private static string Alter(string envelopeB64)
    {
        using var doc = JsonDocument.Parse(Convert.FromBase64String(envelopeB64));
        var fields = new Dictionary<string, object?>();
        foreach (var prop in doc.RootElement.EnumerateObject())
        {
            fields[prop.Name] = prop.Value.ValueKind switch
            {
                JsonValueKind.Number => prop.Value.GetInt64(),
                _ => prop.Value.GetString(),
            };
        }
        var data = Convert.FromBase64String((string)fields["encrypted_data"]!);
        data[0] ^= 0xff;
        fields["encrypted_data"] = Convert.ToBase64String(data);
        return Convert.ToBase64String(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(fields)));
    }

    private static void Check(string what, bool ok)
    {
        Console.WriteLine((ok ? "ok   " : "FAIL ") + what);
        if (!ok) _failures++;
    }

    private static bool ThrowsStale(Action action)
    {
        try { action(); return false; }
        catch (Sealed.StaleEnvelopeException) { return true; }
        catch (Exception e)
        {
            Console.WriteLine($"  wanted StaleEnvelopeException, got {e.GetType().Name}");
            return false;
        }
    }

    private static bool ThrowsCorrupt(Action action)
    {
        try { action(); return false; }
        catch (Sealed.CorruptEnvelopeException) { return true; }
        catch (Exception e)
        {
            Console.WriteLine($"  wanted CorruptEnvelopeException, got {e.GetType().Name}");
            return false;
        }
    }
}
