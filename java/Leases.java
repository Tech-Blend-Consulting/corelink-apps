import java.time.Duration;
import java.time.Instant;
import java.util.List;

/**
 * Leased credentials: request, keep alive while in use, hand back.
 *
 * <p>The other half of what a short-lived credential needs. A secret that rotates is followed by
 * re-reading it; a leased credential expires, and the holder is the only party that knows it is
 * still needed.
 *
 * <p>Renewal bounds itself: CoreLink refuses past the credential's maximum lifetime, so keeping one
 * alive for as long as it is used is not the same as keeping it forever -- which is why keepAlive is
 * safe to run in the background, and why it stops rather than retrying when it is refused.
 *
 * <p>The wire shapes here were verified against a running CoreLink rather than read off the handler:
 * the listing is wrapped in "data" (not "leases") and the credential is a string (not an object).
 * Both were guessed wrong first.
 *
 * <p>See docs/secret-delivery.md.
 */
public final class Leases {

    /** Resource types a credential can be leased against. */
    public static final String RESOURCE_SECRET = "secret";
    public static final String RESOURCE_DATABASE = "database";
    public static final String RESOURCE_CLOUD = "cloud";

    static final List<String> RESOURCE_TYPES =
            List.of(RESOURCE_SECRET, RESOURCE_DATABASE, RESOURCE_CLOUD);

    private Leases() {}

    /**
     * This credential will not extend again.
     *
     * <p>It has reached its maximum lifetime, so retrying is pointless: request a new credential.
     * Distinct from an ordinary failure because the recovery differs, and CoreLink does not say
     * which limit was reached because the action is the same either way.
     */
    public static class LeaseExhausted extends RuntimeException {
        public LeaseExhausted(String message) {
            super(message);
        }
    }

    /**
     * The lease is unknown, already revoked, or belongs to another identity -- deliberately
     * indistinguishable, so a caller learns nothing about leases that are not its own.
     */
    public static class LeaseNotFound extends RuntimeException {
        public LeaseNotFound(String message) {
            super(message);
        }
    }

    /** A credential and the terms it was issued under. */
    public static final class Lease {
        public final String id;
        public final String credential;
        public final String expiresAt;
        public final String issuedAt;

        Lease(String id, String credential, String expiresAt, String issuedAt) {
            this.id = id;
            this.credential = credential == null ? "" : credential;
            this.expiresAt = expiresAt;
            this.issuedAt = issuedAt;
        }

        /** How long this lease has left, as last known. Zero when the expiry cannot be read. */
        public Duration remaining() {
            Instant end = parse(expiresAt);
            if (end == null) {
                return Duration.ZERO;
            }
            Duration left = Duration.between(Instant.now(), end);
            return left.isNegative() ? Duration.ZERO : left;
        }

        /**
         * How long the lease was issued for.
         *
         * <p>CoreLink reports an expiry on issue and not on renewal, so the original term is what
         * later waits are measured from.
         */
        public Duration term(Duration fallback) {
            Instant start = parse(issuedAt);
            Instant end = parse(expiresAt);
            if (start == null || end == null) {
                return fallback;
            }
            Duration t = Duration.between(start, end);
            return t.isNegative() || t.isZero() ? fallback : t;
        }

        /**
         * Redacts the credential.
         *
         * <p>A lease is logged while tracing its lifecycle far more often than a secret is, so its
         * default rendering must not be where the credential escapes.
         */
        @Override
        public String toString() {
            return "Lease[id=" + id + ", expiresAt=" + expiresAt + ", credential=<redacted>]";
        }

        private static Instant parse(String ts) {
            if (ts == null || ts.isEmpty()) {
                return null;
            }
            try {
                return Instant.parse(ts);
            } catch (RuntimeException e) {
                return null;
            }
        }
    }

    /** Build a Lease from either the issue response or a listing row. */
    static Lease fromJson(String json) {
        String id = Sealed.jsonString(json, "lease_id");
        if (id == null || id.isEmpty()) {
            id = Sealed.jsonString(json, "id");
        }
        return new Lease(
                id == null ? "" : id,
                Sealed.jsonString(json, "credential"),
                Sealed.jsonString(json, "expires_at"),
                Sealed.jsonString(json, "issued_at"));
    }
}
