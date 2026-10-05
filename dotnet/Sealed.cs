using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

/// <summary>
/// Opening a sealed envelope.
///
/// The application takes ciphertext from a connector and the key from CoreLink, and opens the
/// secret itself. Nothing between the two holds both halves: the connector is granted
/// secrets:cache and keeps envelopes it has no authority to open, and the application is granted
/// secrets:unwrap and may open one it already has.
///
/// The additional authenticated data is rebuilt here from the secret id and version and required
/// to equal the value stored on the envelope. Decrypting with whatever the envelope carries would
/// detect an altered envelope, because the tag breaks, but would bind nothing -- an envelope
/// claiming to be some other secret would open happily.
///
/// Requires .NET 6+ for AesGcm. See docs/secret-delivery.md.
///
/// Verified against sdk/testdata/sealed_certificate.json and sealed_envelope.json, which the
/// platform's own crypto produces: cd sdk/dotnet &amp;&amp; dotnet run.
/// </summary>
public static class Sealed
{
    /// <summary>
    /// Prefix of the additional authenticated data.
    ///
    /// Must match crypto.SecretAAD on the platform byte for byte: the two are one wire format,
    /// and changing either alone stops every envelope opening. Pinned by
    /// sdk/testdata/sealed_envelope.json.
    /// </summary>
    private const string AadPrefix = "cl.secret.v1";

    /// <summary>AES-GCM's tag, which Go appends to the ciphertext and AesGcm wants separately.</summary>
    private const int TagBytes = 16;

    /// <summary>
    /// A cached envelope the current key will not open.
    ///
    /// Separate from CorruptEnvelopeException because the recoveries differ: ask the connector for
    /// a fresh envelope. A rollback attempt and a damaged envelope look identical at the AEAD and
    /// should not look identical in a log.
    /// </summary>
    public class StaleEnvelopeException : Exception
    {
        public StaleEnvelopeException(string message) : base(message) { }
    }

    /// <summary>
    /// An envelope that did not open and was not stale.
    ///
    /// The key belonged to the version the envelope claims and it still failed, so the ciphertext
    /// or the tag has been altered. Refetching will not help.
    /// </summary>
    public class CorruptEnvelopeException : Exception
    {
        public CorruptEnvelopeException(string message) : base(message) { }
    }

    /// <summary>
    /// A connector answered with a different secret than the one asked for.
    ///
    /// The case the AAD does not cover. An envelope is bound to its own id and version, so another
    /// secret's id and envelope together are internally consistent and open cleanly -- under the
    /// wrong name. A compromised connector can therefore answer a request for one secret with
    /// another the application also holds unwrap on, and every cryptographic check passes.
    ///
    /// CoreLink returns the name the id really belongs to, and the application knows the name it
    /// asked for; neither alone can see the substitution, so the comparison happens in the client.
    /// </summary>
    public class WrongSecretException : Exception
    {
        public WrongSecretException(string message) : base(message) { }
    }

    /// <summary>The additional authenticated data for a secret and version.</summary>
    public static byte[] SecretAad(string secretId, int version) =>
        Encoding.UTF8.GetBytes($"{AadPrefix}|{secretId}|{version}");

    /// <summary>
    /// Open a sealed envelope and return the plaintext bytes.
    ///
    /// <paramref name="dek"/> is the key CoreLink returned for this secret.
    /// <paramref name="secretId"/> and <paramref name="version"/> are the authorized context the
    /// AAD is rebuilt from, not values read out of the envelope.
    /// </summary>
    public static byte[] OpenEnvelope(string envelopeB64, byte[] dek, string secretId, int version)
    {
        byte[] raw;
        try
        {
            raw = Convert.FromBase64String(envelopeB64);
        }
        catch (FormatException e)
        {
            throw new CorruptEnvelopeException("the envelope is not base64: " + e.Message);
        }

        JsonDocument doc;
        try
        {
            doc = JsonDocument.Parse(raw);
        }
        catch (JsonException e)
        {
            throw new CorruptEnvelopeException("the envelope is not an envelope: " + e.Message);
        }

        using (doc)
        {
            var expected = SecretAad(secretId, version);

            // An envelope carrying no AAD was written before binding existed, and opens with none.
            // That is not a rollback -- the thing this must never be confused with -- and the
            // platform skips its own compare for these too. Supplying the expected value here
            // instead would break every secret written before the binding did, which is all of
            // them at a given installation until the first rotation.
            var unbound = true;

            if (doc.RootElement.TryGetProperty("aad", out var aadEl))
            {
                var storedB64 = aadEl.GetString();
                if (!string.IsNullOrEmpty(storedB64))
                {
                    unbound = false;
                    var stored = Convert.FromBase64String(storedB64);
                    if (!stored.AsSpan().SequenceEqual(expected))
                    {
                        // Sealed for a different secret or version. Named as stale rather than
                        // corrupt: the likely cause is a connector holding an old envelope, and
                        // the recovery is to ask it again.
                        throw new StaleEnvelopeException(
                            $"the envelope is bound to something other than {secretId} version {version}");
                    }
                }
            }

            if (!doc.RootElement.TryGetProperty("encrypted_data", out var dataEl) ||
                !doc.RootElement.TryGetProperty("nonce", out var nonceEl))
            {
                throw new CorruptEnvelopeException("the envelope is missing its ciphertext");
            }

            var sealedBytes = Convert.FromBase64String(dataEl.GetString() ?? "");
            var nonce = Convert.FromBase64String(nonceEl.GetString() ?? "");
            if (sealedBytes.Length <= TagBytes)
            {
                throw new CorruptEnvelopeException("the envelope carries no ciphertext");
            }

            // Go appends the tag; AesGcm takes it separately.
            var ciphertext = sealedBytes.AsSpan(0, sealedBytes.Length - TagBytes);
            var tag = sealedBytes.AsSpan(sealedBytes.Length - TagBytes);
            var plaintext = new byte[ciphertext.Length];

            try
            {
                using var gcm = new AesGcm(dek, TagBytes);
                gcm.Decrypt(nonce, ciphertext, tag, plaintext, unbound ? null : expected);
            }
            catch (CryptographicException)
            {
                // The key was for the version the envelope claims and the binding matched, so this
                // is not a rollback: something has been altered.
                throw new CorruptEnvelopeException(
                    "the envelope did not open with the key for its own version");
            }

            return plaintext;
        }
    }

    /// <summary>
    /// The secret's value from a stored record.
    ///
    /// What is sealed is the record, which wraps the value. Older records may be the bare value,
    /// so that is the fallback rather than an error.
    /// </summary>
    public static string ValueFrom(byte[] plaintext)
    {
        var text = Encoding.UTF8.GetString(plaintext);
        try
        {
            using var doc = JsonDocument.Parse(text);
            if (doc.RootElement.ValueKind == JsonValueKind.Object &&
                doc.RootElement.TryGetProperty("value", out var v))
            {
                var value = v.GetString();
                if (!string.IsNullOrEmpty(value))
                {
                    return value;
                }
            }
        }
        catch (JsonException)
        {
            // Not a record; the bare value.
        }
        return text;
    }

    /// <summary>A TLS bundle stored as a secret's value.</summary>
    public sealed record Certificate(string CertificatePem, string PrivateKeyPem, string CaChainPem)
    {
        /// <summary>Never the key. This is handed to a TLS library, not to a log.</summary>
        public override string ToString() =>
            $"Certificate {{ CertificatePem = {CertificatePem[..Math.Min(32, CertificatePem.Length)]}..., "
            + "PrivateKeyPem = <redacted> }}";
    }

    /// <summary>
    /// Parse a TLS bundle out of a secret's value.
    ///
    /// The value is one level deeper than it looks: the stored record wraps it, and for a
    /// certificate the value is itself JSON. ValueFrom unwraps the record, and this parses what
    /// came out.
    ///
    /// Both halves are required. A secret that merely happens to be JSON would otherwise come back
    /// as a certificate with empty fields, which is worse than an error because it fails later and
    /// somewhere else.
    /// </summary>
    public static Certificate CertificateFrom(string value)
    {
        JsonDocument doc;
        try
        {
            doc = JsonDocument.Parse(value);
        }
        catch (JsonException e)
        {
            throw new ArgumentException("not a TLS certificate bundle: " + e.Message, nameof(value));
        }

        using (doc)
        {
            if (doc.RootElement.ValueKind != JsonValueKind.Object)
            {
                throw new ArgumentException("not a TLS certificate bundle", nameof(value));
            }
            var cert = doc.RootElement.TryGetProperty("certificate", out var c) ? c.GetString() ?? "" : "";
            var key = doc.RootElement.TryGetProperty("private_key", out var k) ? k.GetString() ?? "" : "";
            if (cert.Length == 0 || key.Length == 0)
            {
                throw new ArgumentException("carries no certificate and key", nameof(value));
            }
            var chain = doc.RootElement.TryGetProperty("ca_chain", out var ch) ? ch.GetString() ?? "" : "";
            return new Certificate(cert, key, chain);
        }
    }

    /// <summary>
    /// Escape a secret name for a URL, keeping the slashes that are part of it.
    ///
    /// A "." or ".." segment is refused rather than escaped. Clients and servers normalise dot
    /// segments in a path, so such a name would be asked for as a different one, and no secret can
    /// be named that way: the platform's own path validation rejects "..".
    /// </summary>
    public static string EnvelopePath(string name)
    {
        var trimmed = (name ?? "").Trim('/');
        if (trimmed.Length == 0)
        {
            throw new ArgumentException("a secret name is required", nameof(name));
        }

        var parts = trimmed.Split('/');
        for (var i = 0; i < parts.Length; i++)
        {
            if (parts[i].Length == 0)
            {
                throw new ArgumentException($"{name} has an empty path segment", nameof(name));
            }
            if (parts[i] == "." || parts[i] == "..")
            {
                throw new ArgumentException($"{name} is not a secret name", nameof(name));
            }
            parts[i] = Uri.EscapeDataString(parts[i]);
        }
        return string.Join("/", parts);
    }
}
