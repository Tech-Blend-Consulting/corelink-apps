import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Opening a sealed envelope.
 *
 * <p>The application takes ciphertext from a connector and the key from CoreLink, and opens the
 * secret itself. Nothing between the two holds both halves: the connector is granted
 * {@code secrets:cache} and keeps envelopes it has no authority to open, and the application is
 * granted {@code secrets:unwrap} and may open one it already has.
 *
 * <p>The additional authenticated data is rebuilt here from the secret id and version and required
 * to equal the value stored on the envelope. Decrypting with whatever the envelope carries would
 * detect an altered envelope, because the tag breaks, but would bind nothing -- an envelope
 * claiming to be some other secret would open happily.
 *
 * <p>See docs/secret-delivery.md.
 */
public final class Sealed {

    /**
     * Prefix of the additional authenticated data.
     *
     * <p>Must match {@code crypto.SecretAAD} on the platform byte for byte: the two are one wire
     * format, and changing either alone stops every envelope opening. Pinned by
     * {@code sdk/testdata/sealed_envelope.json}, which the platform produces.
     */
    private static final String AAD_PREFIX = "cl.secret.v1";

    /** AES-GCM's tag length in bits, as Java wants it. */
    private static final int TAG_BITS = 128;

    private Sealed() {}

    /**
     * A cached envelope the current key will not open.
     *
     * <p>Separate from {@link CorruptEnvelope} because the recoveries differ: ask the connector for
     * a fresh envelope. A rollback attempt and a damaged envelope look identical at the AEAD and
     * should not look identical in a log.
     */
    public static class StaleEnvelope extends RuntimeException {
        public StaleEnvelope(String message) {
            super(message);
        }
    }

    /**
     * An envelope that did not open and was not stale.
     *
     * <p>The key belonged to the version the envelope claims and it still failed, so the ciphertext
     * or the tag has been altered. Refetching will not help.
     */
    public static class CorruptEnvelope extends RuntimeException {
        public CorruptEnvelope(String message) {
            super(message);
        }
    }

    /**
     * A connector answered with a different secret than the one asked for.
     *
     * <p>The case the AAD does not cover. An envelope is bound to its own id and version, so
     * another secret's id and envelope together are internally consistent and open cleanly --
     * under the wrong name. A compromised connector can therefore answer a request for one secret
     * with another the application also holds unwrap on, and every cryptographic check passes.
     *
     * <p>CoreLink returns the name the id really belongs to, and the application knows the name it
     * asked for; neither alone can see the substitution, so the comparison happens in the client.
     */
    public static class WrongSecret extends RuntimeException {
        public WrongSecret(String message) {
            super(message);
        }
    }

    /** The additional authenticated data for a secret and version. */
    public static byte[] secretAad(String secretId, int version) {
        return (AAD_PREFIX + "|" + secretId + "|" + version).getBytes(StandardCharsets.UTF_8);
    }

    /**
     * Open a sealed envelope and return the plaintext bytes.
     *
     * @param envelopeB64 base64 of the stored envelope, as a connector serves it
     * @param dek the key CoreLink returned for this secret
     * @param secretId the authorized context the AAD is rebuilt from, not a value read out of the
     *     envelope
     * @param version likewise
     */
    public static byte[] openEnvelope(String envelopeB64, byte[] dek, String secretId, int version) {
        byte[] raw;
        try {
            raw = Base64.getDecoder().decode(envelopeB64);
        } catch (IllegalArgumentException e) {
            throw new CorruptEnvelope("the envelope is not base64: " + e.getMessage());
        }
        String body = new String(raw, StandardCharsets.UTF_8);

        byte[] expected = secretAad(secretId, version);

        String storedAad = jsonString(body, "aad");
        // An envelope carrying no AAD was written before binding existed, and opens with none.
        // That is not a rollback -- the thing this must never be confused with -- and the platform
        // skips its own compare for these too. Supplying the expected value here instead would
        // break every secret written before the binding did, which is all of them at a given
        // installation until the first rotation.
        boolean unbound = storedAad == null || storedAad.isEmpty();
        if (!unbound) {
            byte[] stored = Base64.getDecoder().decode(storedAad);
            if (!java.util.Arrays.equals(stored, expected)) {
                // Sealed for a different secret or version. Named as stale rather than corrupt:
                // the likely cause is a connector holding an old envelope, and the recovery is to
                // ask it again.
                throw new StaleEnvelope(
                        "the envelope is bound to something other than " + secretId + " version " + version);
            }
        }

        String dataB64 = jsonString(body, "encrypted_data");
        String nonceB64 = jsonString(body, "nonce");
        if (dataB64 == null || nonceB64 == null) {
            throw new CorruptEnvelope("the envelope is missing its ciphertext");
        }
        byte[] sealed = Base64.getDecoder().decode(dataB64);
        byte[] nonce = Base64.getDecoder().decode(nonceB64);

        try {
            // Java takes the ciphertext with its tag appended, which is how Go writes it.
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(
                    Cipher.DECRYPT_MODE,
                    new SecretKeySpec(dek, "AES"),
                    new GCMParameterSpec(TAG_BITS, nonce));
            if (!unbound) {
                cipher.updateAAD(expected);
            }
            return cipher.doFinal(sealed);
        } catch (Exception e) {
            // The key was for the version the envelope claims and the binding matched, so this is
            // not a rollback: something has been altered.
            throw new CorruptEnvelope("the envelope did not open with the key for its own version");
        }
    }

    /**
     * The secret's value from a stored record.
     *
     * <p>What is sealed is the record, which wraps the value. Older records may be the bare value,
     * so that is the fallback rather than an error.
     */
    public static String valueFrom(byte[] plaintext) {
        String text = new String(plaintext, StandardCharsets.UTF_8);
        String value = jsonString(text, "value");
        return value != null ? value : text;
    }

    /** A TLS bundle stored as a secret's value. */
    public static final class Certificate {
        public final String certificate;
        public final String privateKey;
        public final String caChain;

        Certificate(String certificate, String privateKey, String caChain) {
            this.certificate = certificate;
            this.privateKey = privateKey;
            this.caChain = caChain;
        }

        /** Never the key. This is handed to a TLS library, not to a log. */
        @Override
        public String toString() {
            return "Certificate[certificate=" + certificate.substring(0, Math.min(32, certificate.length()))
                    + "..., privateKey=<redacted>]";
        }
    }

    /**
     * Parse a TLS bundle out of a secret's value.
     *
     * <p>The value is one level deeper than it looks: the stored record wraps it, and for a
     * certificate the value is itself JSON. {@link #valueFrom} unwraps the record, and this parses
     * what came out.
     *
     * <p>Both halves are required. A secret that merely happens to be JSON would otherwise come
     * back as a certificate with empty fields, which is worse than an error because it fails later
     * and somewhere else.
     */
    public static Certificate certificateFrom(String value) {
        String cert = jsonString(value, "certificate");
        String key = jsonString(value, "private_key");
        if (cert == null || cert.isEmpty() || key == null || key.isEmpty()) {
            throw new IllegalArgumentException("not a TLS certificate bundle with both halves");
        }
        String chain = jsonString(value, "ca_chain");
        return new Certificate(cert, key, chain == null ? "" : chain);
    }

    /**
     * Escape a secret name for a URL, keeping the slashes that are part of it.
     *
     * <p>A "." or ".." segment is refused rather than escaped. Clients and servers normalise dot
     * segments in a path, so such a name would be asked for as a different one, and no secret can
     * be named that way: the platform's own path validation rejects "..".
     */
    public static String envelopePath(String name) {
        String trimmed = name == null ? "" : name.replaceAll("^/+", "").replaceAll("/+$", "");
        if (trimmed.isEmpty()) {
            throw new IllegalArgumentException("a secret name is required");
        }
        String[] parts = trimmed.split("/", -1);
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < parts.length; i++) {
            String part = parts[i];
            if (part.isEmpty()) {
                throw new IllegalArgumentException(name + " has an empty path segment");
            }
            if (part.equals(".") || part.equals("..")) {
                throw new IllegalArgumentException(name + " is not a secret name");
            }
            if (i > 0) {
                out.append('/');
            }
            // URLEncoder is form encoding, where a space becomes '+'. In a path it must be %20.
            out.append(URLEncoder.encode(part, StandardCharsets.UTF_8).replace("+", "%20"));
        }
        return out.toString();
    }

    /**
     * Read one string field out of a flat JSON object.
     *
     * <p>Deliberately not a JSON parser. This SDK is a single file with no dependencies, and the
     * two shapes it reads -- an envelope and a one-field record -- are produced by the platform,
     * not by users. Returns null when the field is absent.
     */
    static String jsonString(String json, String field) {
        String needle = "\"" + field + "\"";
        int at = json.indexOf(needle);
        if (at < 0) {
            return null;
        }
        int colon = json.indexOf(':', at + needle.length());
        if (colon < 0) {
            return null;
        }
        int open = json.indexOf('"', colon + 1);
        if (open < 0) {
            return null;
        }
        StringBuilder out = new StringBuilder();
        for (int i = open + 1; i < json.length(); i++) {
            char c = json.charAt(i);
            if (c == '\\' && i + 1 < json.length()) {
                char next = json.charAt(++i);
                switch (next) {
                    case 'n': out.append('\n'); break;
                    case 't': out.append('\t'); break;
                    case 'r': out.append('\r'); break;
                    default: out.append(next);
                }
                continue;
            }
            if (c == '"') {
                return out.toString();
            }
            out.append(c);
        }
        return null;
    }
}
