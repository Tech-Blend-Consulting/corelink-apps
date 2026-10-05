using System.Text.Json;

/// <summary>
/// Leased credentials: request, keep alive while in use, hand back.
///
/// The other half of what a short-lived credential needs. A secret that rotates is followed by
/// re-reading it; a leased credential expires, and the holder is the only party that knows it is
/// still needed.
///
/// Renewal bounds itself: CoreLink refuses past the credential's maximum lifetime, so keeping one
/// alive for as long as it is used is not the same as keeping it forever.
///
/// The wire shapes here were verified against a running CoreLink rather than read off the handler:
/// the listing is wrapped in "data" (not "leases") and the credential is a string (not an object).
/// Both were guessed wrong first.
///
/// See docs/secret-delivery.md.
/// </summary>
public static class Leases
{
    /// <summary>Resource types a credential can be leased against.</summary>
    public const string ResourceSecret = "secret";
    public const string ResourceDatabase = "database";
    public const string ResourceCloud = "cloud";

    internal static readonly string[] ResourceTypes = { ResourceSecret, ResourceDatabase, ResourceCloud };

    /// <summary>
    /// This credential will not extend again.
    ///
    /// It has reached its maximum lifetime, so retrying is pointless: request a new credential.
    /// Distinct from an ordinary failure because the recovery differs, and CoreLink does not say
    /// which limit was reached because the action is the same either way.
    /// </summary>
    public class LeaseExhaustedException : Exception
    {
        public LeaseExhaustedException(string message) : base(message) { }
    }

    /// <summary>
    /// The lease is unknown, already revoked, or belongs to another identity -- deliberately
    /// indistinguishable, so a caller learns nothing about leases that are not its own.
    /// </summary>
    public class LeaseNotFoundException : Exception
    {
        public LeaseNotFoundException(string message) : base(message) { }
    }

    /// <summary>A credential and the terms it was issued under.</summary>
    public sealed class Lease
    {
        public string Id { get; }
        public string Credential { get; }
        public DateTimeOffset? ExpiresAt { get; }
        public DateTimeOffset? IssuedAt { get; }

        internal Lease(string id, string credential, DateTimeOffset? expiresAt, DateTimeOffset? issuedAt)
        {
            Id = id;
            Credential = credential ?? "";
            ExpiresAt = expiresAt;
            IssuedAt = issuedAt;
        }

        /// <summary>How long this lease has left, as last known. Zero when there is no expiry.</summary>
        public TimeSpan Remaining =>
            ExpiresAt is null ? TimeSpan.Zero
                : (ExpiresAt.Value - DateTimeOffset.UtcNow) is var left && left > TimeSpan.Zero
                    ? left : TimeSpan.Zero;

        /// <summary>
        /// How long the lease was issued for.
        ///
        /// CoreLink reports an expiry on issue and not on renewal, so the original term is what
        /// later waits are measured from.
        /// </summary>
        public TimeSpan Term(TimeSpan fallback)
        {
            if (IssuedAt is null || ExpiresAt is null) return fallback;
            var t = ExpiresAt.Value - IssuedAt.Value;
            return t > TimeSpan.Zero ? t : fallback;
        }

        /// <summary>
        /// Redacts the credential.
        ///
        /// A lease is logged while tracing its lifecycle far more often than a secret is, so its
        /// default rendering must not be where the credential escapes.
        /// </summary>
        public override string ToString() =>
            $"Lease {{ Id = {Id}, ExpiresAt = {ExpiresAt:o}, Credential = <redacted> }}";
    }

    /// <summary>Build a Lease from either the issue response or a listing row.</summary>
    internal static Lease FromElement(JsonElement el)
    {
        var id = Str(el, "lease_id");
        if (string.IsNullOrEmpty(id)) id = Str(el, "id");
        return new Lease(id ?? "", Str(el, "credential") ?? "", Stamp(el, "expires_at"), Stamp(el, "issued_at"));
    }

    private static string? Str(JsonElement el, string name) =>
        el.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

    private static DateTimeOffset? Stamp(JsonElement el, string name)
    {
        var raw = Str(el, name);
        if (string.IsNullOrEmpty(raw)) return null;
        return DateTimeOffset.TryParse(raw, out var parsed) ? parsed : null;
    }
}
