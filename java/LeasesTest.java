import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * The leased-credential lifecycle against a fake CoreLink.
 *
 * <p>The wire shapes are the ones a live CoreLink was observed to send -- the listing wrapped in
 * "data", the credential as a string -- because the Go SDK guessed both wrong from reading the
 * handler and only a real call disagreed.
 *
 * <p>Run: cd sdk/java &amp;&amp; javac Sealed.java Leases.java TransitClient.java LeasesTest.java
 * &amp;&amp; java LeasesTest
 *
 * <p>Plain main rather than JUnit, and the JDK's own HTTP server rather than a mock library, because
 * this SDK is dependency-free and a test framework would be its only dependency.
 */
public class LeasesTest {

    private static int failures = 0;
    private static final AtomicInteger renewals = new AtomicInteger();
    private static int renewLimit = 0;
    private static String lastReleased = "";
    private static String lastRequestBody = "";

    public static void main(String[] args) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);

        server.createContext("/api/v1/nhi-agent/credentials", exchange -> {
            String method = exchange.getRequestMethod();
            String path = exchange.getRequestURI().getPath();
            String body;
            int status = 200;

            if (method.equals("POST")) {
                lastRequestBody = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
                Instant now = Instant.now();
                body = "{\"lease_id\":\"lease-1\",\"credential\":\"{\\\"username\\\":\\\"dyn_abc\\\"}\","
                        + "\"issued_at\":\"" + now + "\",\"expires_at\":\"" + now.plusSeconds(900) + "\"}";
            } else if (method.equals("DELETE")) {
                lastReleased = path.substring(path.lastIndexOf('/') + 1);
                status = 204;
                body = "";
            } else {
                // "data", not "leases".
                body = "{\"data\":[{\"id\":\"lease-1\",\"expires_at\":\"" + Instant.now().plusSeconds(900) + "\"}]}";
            }

            byte[] out = body.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(status, out.length == 0 ? -1 : out.length);
            if (out.length > 0) {
                exchange.getResponseBody().write(out);
            }
            exchange.close();
        });

        server.createContext("/api/v1/nhi-agent/leases", exchange -> {
            int status;
            if (exchange.getRequestURI().getPath().contains("unknown-lease")) {
                status = 404;
            } else if (renewLimit > 0 && renewals.get() >= renewLimit) {
                status = 422;
            } else {
                renewals.incrementAndGet();
                status = 200;
            }
            byte[] out = "{\"renewed\":true}".getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(status, out.length);
            exchange.getResponseBody().write(out);
            exchange.close();
        });

        server.start();
        String url = "http://127.0.0.1:" + server.getAddress().getPort();

        try (TransitClient client = new TransitClient("http://127.0.0.1:1", url, "nhi-1")) {
            client.setSessionForTesting("session-in-place");

            Leases.Lease lease = client.requestCredential(Leases.RESOURCE_SECRET, "secret-1", 300);
            check("a credential is leased with its terms",
                    lease.id.equals("lease-1")
                            && lease.credential.contains("dyn_abc")
                            && lease.expiresAt != null
                            && !lease.remaining().isZero());
            check("the requested TTL is sent", lastRequestBody.contains("\"ttl_seconds\":300"));

            // A lease is logged while tracing its lifecycle; its rendering must not leak.
            check("the rendering does not carry the credential",
                    !lease.toString().contains("dyn_abc"));

            check("an unknown resource type is refused locally",
                    throwsIllegalArgument(() -> client.requestCredential("kubernetes", "x", 0)));
            check("an empty resource id is refused locally",
                    throwsIllegalArgument(() -> client.requestCredential(Leases.RESOURCE_SECRET, "", 0)));

            client.renewLease("lease-1");
            check("a renewal that works reports nothing", renewals.get() == 1);

            renewLimit = 1;
            check("an exhausted lease is named as such",
                    throwsExhausted(() -> client.renewLease("lease-1")));
            check("an unknown lease is not found",
                    throwsNotFound(() -> client.renewLease("unknown-lease")));

            client.releaseCredential("lease-1");
            check("release names the lease", lastReleased.equals("lease-1"));
            // Releasing twice must not be an error: the caller's intent is satisfied.
            client.releaseCredential("lease-1");
            check("release is idempotent", true);

            List<Leases.Lease> found = client.listLeases();
            check("the listing names the lease", found.size() == 1 && found.get(0).id.equals("lease-1"));
            check("the listing omits the credential", found.get(0).credential.isEmpty());

            check("term falls back when the timestamps are absent",
                    new Leases.Lease("x", "", null, null).term(Duration.ofMinutes(1))
                            .equals(Duration.ofMinutes(1)));
        } finally {
            server.stop(0);
        }

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

    private interface Action {
        void run() throws Exception;
    }

    private static boolean throwsIllegalArgument(Action a) {
        try {
            a.run();
            return false;
        } catch (IllegalArgumentException e) {
            return true;
        } catch (Exception e) {
            System.out.println("  wanted IllegalArgumentException, got " + e.getClass().getSimpleName());
            return false;
        }
    }

    private static boolean throwsExhausted(Action a) {
        try {
            a.run();
            return false;
        } catch (Leases.LeaseExhausted e) {
            return true;
        } catch (Exception e) {
            System.out.println("  wanted LeaseExhausted, got " + e.getClass().getSimpleName());
            return false;
        }
    }

    private static boolean throwsNotFound(Action a) {
        try {
            a.run();
            return false;
        } catch (Leases.LeaseNotFound e) {
            return true;
        } catch (Exception e) {
            System.out.println("  wanted LeaseNotFound, got " + e.getClass().getSimpleName());
            return false;
        }
    }
}
