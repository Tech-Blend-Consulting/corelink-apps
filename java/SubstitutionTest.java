import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * A connector that answers with a different secret than the one asked for.
 *
 * <p>The attack the AAD does not cover. An envelope is bound to its own id and version, so a
 * substituted secret is internally consistent: the key CoreLink returns for that id opens it, the
 * version matches, the tag verifies. Every cryptographic check passes and the application gets a
 * value it did not ask for.
 *
 * <p>The fixture is a real one, produced by the platform's own crypto, served under the wrong name.
 * Nothing is forged -- that is the point. The only thing that can catch it is comparing the name
 * CoreLink says the id belongs to against the name the application asked for.
 *
 * <p>Run: cd sdk/java &amp;&amp; javac Sealed.java Leases.java TransitClient.java
 * SubstitutionTest.java &amp;&amp; java SubstitutionTest
 *
 * <p>Plain main rather than JUnit, and the JDK's own HTTP server rather than a mock library,
 * because this SDK is dependency-free and a test framework would be its only dependency.
 */
public class SubstitutionTest {

    private static int failures = 0;

    // The name the fixture's secret really has, and the name the application asks for. The
    // connector answers the second with the first.
    private static final String REAL_NAME = "production/other-secret";
    private static final String ASKED_NAME = "production/dbone";

    // What the unwrap endpoint reports as the authoritative name; set per case.
    private static volatile String authoritativeName = REAL_NAME;

    private static String fxSecretId;
    private static String fxEnvelope;
    private static String fxDek;
    private static int fxVersion;
    private static String fxExpectedValue;

    public static void main(String[] args) throws Exception {
        loadFixture();

        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);

        // The connector: asked for one name, answers with the other secret's id and envelope. A
        // real envelope, just not the requested one.
        server.createContext("/v1/envelopes/", exchange -> send(exchange, 200,
            "{\"secret_id\":\"" + fxSecretId + "\",\"name\":\"" + ASKED_NAME + "\",\"version\":"
                + fxVersion + ",\"envelope\":\"" + fxEnvelope + "\"}"));

        // CoreLink: unwraps its own copy and says which name the id belongs to.
        server.createContext("/api/v1/nhi-agent/secrets/", exchange -> send(exchange, 200,
            "{\"dek\":\"" + fxDek + "\",\"version\":" + fxVersion + ",\"name\":\""
                + authoritativeName + "\"}"));

        server.start();
        String base = "http://127.0.0.1:" + server.getAddress().getPort();

        try {
            TransitClient client = new TransitClient(base, base, "nhi-1");
            client.setSessionForTesting("session-in-place");

            authoritativeName = REAL_NAME;
            try {
                client.getSecretSealed(ASKED_NAME);
                fail("a substituted secret was accepted");
            } catch (Sealed.WrongSecret e) {
                // The message has to name both, or an operator cannot tell which connector lied
                // about what.
                check(e.getMessage().contains(ASKED_NAME), "the refusal does not name what was asked for");
                check(e.getMessage().contains(REAL_NAME), "the refusal does not name what was served");
            }

            // The same path with the names agreeing: proves the check refuses substitution rather
            // than refusing everything.
            authoritativeName = ASKED_NAME;
            check(fxExpectedValue.equals(client.getSecretSealed(ASKED_NAME)),
                "the right secret did not open");

            // An older CoreLink that does not send the name yet. Refusing here would break every
            // application against it; the AAD still binds id and version.
            authoritativeName = "";
            check(fxExpectedValue.equals(client.getSecretSealed(ASKED_NAME)),
                "a platform sending no name was refused");
        } finally {
            server.stop(0);
        }

        if (failures > 0) {
            System.out.println(failures + " failure(s)");
            System.exit(1);
        }
        System.out.println("SubstitutionTest: ok");
    }

    private static void send(com.sun.net.httpserver.HttpExchange exchange, int status, String body)
        throws IOException {
        byte[] out = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, out.length);
        exchange.getResponseBody().write(out);
        exchange.close();
    }

    private static void loadFixture() throws IOException {
        String json = Files.readString(Path.of("..", "testdata", "sealed_envelope.json"));
        fxSecretId = jsonString(json, "secret_id");
        fxEnvelope = jsonString(json, "envelope");
        fxDek = jsonString(json, "dek");
        fxExpectedValue = jsonString(json, "expected_value");
        fxVersion = Integer.parseInt(jsonRaw(json, "version"));
    }

    private static String jsonString(String json, String key) {
        String needle = "\"" + key + "\"";
        int at = json.indexOf(needle);
        if (at < 0) throw new IllegalStateException("fixture has no " + key);
        int open = json.indexOf('"', json.indexOf(':', at) + 1);
        int close = json.indexOf('"', open + 1);
        return json.substring(open + 1, close);
    }

    private static String jsonRaw(String json, String key) {
        String needle = "\"" + key + "\"";
        int at = json.indexOf(needle);
        int colon = json.indexOf(':', at);
        int end = colon + 1;
        while (end < json.length() && "-0123456789".indexOf(json.charAt(end)) < 0) end++;
        int start = end;
        while (end < json.length() && "-0123456789".indexOf(json.charAt(end)) >= 0) end++;
        return json.substring(start, end);
    }

    private static void check(boolean ok, String message) {
        if (!ok) fail(message);
    }

    private static void fail(String message) {
        System.out.println("FAIL: " + message);
        failures++;
    }
}
