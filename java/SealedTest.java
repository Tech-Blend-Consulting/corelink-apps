import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Base64;

/**
 * The sealed envelope, opened against a fixture the platform produced.
 *
 * <p>The fixture comes from internal/crypto, which is what CoreLink stores and what the unwrap
 * endpoint returns, so this checks agreement with the platform rather than agreement with itself.
 *
 * <p>Regenerate: {@code go test ./internal/crypto/ -run TestSDKFixture -update}
 *
 * <p>Run: {@code cd sdk/java && javac Sealed.java SealedTest.java && java SealedTest}
 *
 * <p>Plain main rather than JUnit, because this SDK is a single dependency-free file and adding a
 * test framework to it would be the only dependency in the tree.
 */
public class SealedTest {

    private static int failures = 0;

    public static void main(String[] args) throws Exception {
        String json = Files.readString(Path.of("..", "testdata", "sealed_envelope.json"));

        String secretId = Sealed.jsonString(json, "secret_id");
        int version = Integer.parseInt(numberField(json, "version"));
        String envelope = Sealed.jsonString(json, "envelope");
        byte[] dek = Base64.getDecoder().decode(Sealed.jsonString(json, "dek"));
        byte[] aad = Base64.getDecoder().decode(Sealed.jsonString(json, "aad"));
        String expectedPlaintext = Sealed.jsonString(json, "expected_plaintext");
        String expectedValue = Sealed.jsonString(json, "expected_value");

        // One wire format shared with crypto.SecretAAD. If this drifts, nothing opens, so it is
        // checked against bytes the platform wrote.
        check("the AAD matches the platform's",
                Arrays.equals(Sealed.secretAad(secretId, version), aad));

        byte[] plaintext = Sealed.openEnvelope(envelope, dek, secretId, version);
        check("it opens what the platform sealed",
                new String(plaintext, StandardCharsets.UTF_8).equals(expectedPlaintext));
        check("the value comes out of the record",
                Sealed.valueFrom(plaintext).equals(expectedValue));

        // What makes a stale cached envelope fail closed rather than being served as though it
        // were current.
        check("the wrong version does not open it",
                throwsStale(() -> Sealed.openEnvelope(envelope, dek, secretId, version + 1)));

        // The case authorization cannot catch: the caller may hold unwrap on both secrets, so only
        // the binding can stop this.
        check("a false secret id does not open it",
                throwsStale(() -> Sealed.openEnvelope(
                        envelope, dek, "00000000-0000-0000-0000-000000000000", version)));

        check("another key does not open it",
                throwsCorrupt(() -> Sealed.openEnvelope(envelope, new byte[32], secretId, version)));

        check("envelopePath keeps slashes",
                Sealed.envelopePath("production/dbone").equals("production/dbone")
                        && Sealed.envelopePath("/production/dbone/").equals("production/dbone")
                        && Sealed.envelopePath("prod/db one").equals("prod/db%20one"));

        boolean dotsRefused = true;
        for (String bad : new String[] {"prod/../etc/passwd", "prod/.", "..", "prod//dbone", "", "/"}) {
            boolean refused = false;
            try {
                Sealed.envelopePath(bad);
            } catch (IllegalArgumentException e) {
                refused = true;
            }
            if (!refused) {
                System.out.println("  " + bad + " was not refused");
                dotsRefused = false;
            }
        }
        check("envelopePath refuses dot segments", dotsRefused);

        // A certificate comes back one level deeper than a password: the stored record wraps the
        // value, and for a certificate the value is itself JSON. An SDK that returned the record
        // rather than its value would look correct on a password and produce an empty certificate
        // here, so this runs the whole local chain against a bundle the platform sealed.
        String certJson = Files.readString(Path.of("..", "testdata", "sealed_certificate.json"));
        String certEnvelope = Sealed.jsonString(certJson, "envelope");
        byte[] certDek = Base64.getDecoder().decode(Sealed.jsonString(certJson, "dek"));
        String certSecretId = Sealed.jsonString(certJson, "secret_id");
        int certVersion = Integer.parseInt(numberField(certJson, "version"));
        String certExpectedValue = Sealed.jsonString(certJson, "expected_value");

        byte[] certPlaintext = Sealed.openEnvelope(certEnvelope, certDek, certSecretId, certVersion);
        String certValue = Sealed.valueFrom(certPlaintext);
        check("the certificate chain produces the sealed bundle", certValue.equals(certExpectedValue));

        Sealed.Certificate bundle = Sealed.certificateFrom(certValue);
        check("the bundle's parts come out",
                bundle.certificate.contains("BEGIN CERTIFICATE")
                        && bundle.privateKey.contains("BEGIN PRIVATE KEY")
                        && bundle.caChain.contains("BEGIN CERTIFICATE"));

        check("the toString does not carry the key",
                !new Sealed.Certificate("cert-pem", "super-secret-key", "").toString()
                        .contains("super-secret-key"));

        boolean nonBundlesRefused = true;
        for (String bad : new String[] {
                "{\"value\":\"a-password\"}", "a-bare-password", "{}",
                "{\"certificate\":\"c\"}", "{\"private_key\":\"k\"}", "[]"}) {
            boolean refused = false;
            try {
                Sealed.certificateFrom(bad);
            } catch (IllegalArgumentException e) {
                refused = true;
            }
            if (!refused) {
                System.out.println("  " + bad + " was not refused as a bundle");
                nonBundlesRefused = false;
            }
        }
        check("a secret that is not a bundle is refused", nonBundlesRefused);

        // An envelope written before binding existed carries no AAD, and opens.
        //
        // Not a rollback -- the thing this must never be confused with. The platform skips its own
        // compare for these, so an SDK that insisted on the expected AAD would call every
        // pre-binding secret corrupt. All twenty of production's versions were unbound when this
        // was measured, so that SDK could not read a single real secret.
        String legacyJson = Files.readString(Path.of("..", "testdata", "sealed_legacy_no_aad.json"));
        String legacyEnvelope = Sealed.jsonString(legacyJson, "envelope");
        byte[] legacyDek = Base64.getDecoder().decode(Sealed.jsonString(legacyJson, "dek"));
        String legacySecretId = Sealed.jsonString(legacyJson, "secret_id");
        int legacyVersion = Integer.parseInt(numberField(legacyJson, "version"));
        String legacyExpected = Sealed.jsonString(legacyJson, "expected_value");

        byte[] legacyPlaintext =
                Sealed.openEnvelope(legacyEnvelope, legacyDek, legacySecretId, legacyVersion);
        check("a pre-binding envelope opens and is not called corrupt",
                Sealed.valueFrom(legacyPlaintext).equals(legacyExpected));

        // Unbound does not mean unchecked.
        boolean wrongKeyRefused = false;
        try {
            Sealed.openEnvelope(legacyEnvelope, new byte[32], legacySecretId, legacyVersion);
        } catch (Sealed.CorruptEnvelope e) {
            wrongKeyRefused = true;
        }
        check("a pre-binding envelope still needs the right key", wrongKeyRefused);

        if (failures > 0) {
            System.out.println(failures + " failed");
            System.exit(1);
        }
        System.out.println("all passed");
    }

    private static void check(String what, boolean ok) {
        System.out.println((ok ? "ok   " : "FAIL ") + what);
        if (!ok) {
            failures++;
        }
    }

    private static boolean throwsStale(Runnable r) {
        try {
            r.run();
            return false;
        } catch (Sealed.StaleEnvelope e) {
            return true;
        } catch (RuntimeException e) {
            System.out.println("  wanted StaleEnvelope, got " + e.getClass().getSimpleName());
            return false;
        }
    }

    private static boolean throwsCorrupt(Runnable r) {
        try {
            r.run();
            return false;
        } catch (Sealed.CorruptEnvelope e) {
            return true;
        } catch (RuntimeException e) {
            System.out.println("  wanted CorruptEnvelope, got " + e.getClass().getSimpleName());
            return false;
        }
    }

    /** Read one numeric field out of the flat fixture. */
    private static String numberField(String json, String field) {
        int at = json.indexOf("\"" + field + "\"");
        int colon = json.indexOf(':', at);
        int end = colon + 1;
        while (end < json.length() && json.charAt(end) != ',' && json.charAt(end) != '\n') {
            end++;
        }
        return json.substring(colon + 1, end).trim();
    }
}
