import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * The deployment file reader, against the cases every SDK shares.
 *
 * <p>Six hand-written readers drift unless one thing pins them.
 * sdk/testdata/deployment_cases.json is that thing: the accepted files with their expected result,
 * and the rejected files that must be refused rather than read as something their author did not
 * write.
 *
 * <p>Run: cd sdk/java &amp;&amp; javac Sealed.java Leases.java TransitClient.java Deployment.java
 * DeploymentTest.java &amp;&amp; java DeploymentTest
 *
 * <p>Plain main rather than JUnit, because this SDK is dependency-free and a test framework would be
 * its only dependency. The JSON reader below exists for the same reason -- it reads the one shape
 * this fixture has and nothing else, and its correctness is checked against the case counts the
 * other SDKs see.
 */
public class DeploymentTest {

    private static int failures = 0;

    public static void main(String[] args) throws Exception {
        String json = Files.readString(Path.of("..", "testdata", "deployment_cases.json"));

        List<Case> accepted = readCases(json, "accepted");
        List<Case> rejected = readCases(json, "rejected");

        // The counts are the first check: a JSON reader that quietly dropped cases would make
        // every assertion below pass by not running.
        check("the fixture has accepted cases", accepted.size() >= 10);
        check("the fixture has rejected cases", rejected.size() >= 20);

        for (Case c : accepted) {
            Deployment d;
            try {
                d = loadText(c.text);
            } catch (RuntimeException e) {
                fail("accepted/" + c.name + ": refused a file the other SDKs accept: " + e.getMessage());
                continue;
            }
            if (!d.nhiId.equals(c.nhiId)) {
                fail("accepted/" + c.name + ": nhiId = " + d.nhiId + ", want " + c.nhiId);
            }
            if (!d.serviceAccount.equals(c.serviceAccount)) {
                fail("accepted/" + c.name + ": serviceAccount = " + d.serviceAccount
                    + ", want " + c.serviceAccount);
            }
            if (!String.join(",", d.secrets).equals(String.join(",", c.secrets))) {
                fail("accepted/" + c.name + ": secrets = " + d.secrets + ", want " + c.secrets);
            }
        }
        check("every accepted case parses to the shared result", failures == 0);

        int before = failures;
        for (Case c : rejected) {
            boolean refused = false;
            try {
                loadText(c.text);
            } catch (RuntimeException e) {
                refused = true;
            }
            if (!refused) {
                fail("rejected/" + c.name + ": accepted a file the other SDKs refuse; it should "
                    + "fail rather than be read as something its author did not write");
            }
        }
        check("every rejected case is refused", failures == before);

        // The ServiceAccount check only speaks when it can see a disagreement.
        String payload = base64Url("{\"sub\":\"system:serviceaccount:prod:billing\"}");
        check("it reads the name out of a projected token",
            "billing".equals(Deployment.serviceAccountFromToken("x." + payload + ".y")));
        check("junk is no opinion", Deployment.serviceAccountFromToken("not-a-token") == null);

        // A missing file is not an error for the optional loader.
        Path missing = Path.of(System.getProperty("java.io.tmpdir"), "corelink-absent-" + System.nanoTime());
        check("a missing file is not an error for the optional loader",
            Deployment.loadIfPresent(missing.toString()) == null);

        if (failures > 0) {
            System.out.println(failures + " failure(s)");
            System.exit(1);
        }
        System.out.println("DeploymentTest: ok (" + accepted.size() + " accepted, "
            + rejected.size() + " rejected)");
    }

    /** Run the whole load, so the shared cases exercise what an application calls. */
    private static Deployment loadText(String text) throws Exception {
        Path dir = Files.createTempDirectory("deployment");
        try {
            Path p = dir.resolve("secrets.yaml");
            Files.writeString(p, text);
            return Deployment.load(p.toString());
        } finally {
            Files.deleteIfExists(dir.resolve("secrets.yaml"));
            Files.deleteIfExists(dir);
        }
    }

    private static String base64Url(String s) {
        return java.util.Base64.getUrlEncoder().withoutPadding()
            .encodeToString(s.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }

    private static final class Case {
        String name = "";
        String text = "";
        String nhiId = "";
        String serviceAccount = "";
        List<String> secrets = new ArrayList<>();
    }

    // A reader for the one shape this fixture has: {"accepted":[{...}],"rejected":[{...}]} where
    // every value is a string or an array of strings. Written out rather than pulled in, for the
    // same reason the SDK has no dependencies.

    private static List<Case> readCases(String json, String key) {
        int at = json.indexOf("\"" + key + "\"");
        if (at < 0) {
            throw new IllegalStateException("the fixture has no " + key);
        }
        int open = json.indexOf('[', at);
        List<Case> out = new ArrayList<>();
        int[] cursor = {open + 1};
        while (true) {
            skipSpace(json, cursor);
            char c = json.charAt(cursor[0]);
            if (c == ']') {
                break;
            }
            if (c == ',') {
                cursor[0]++;
                continue;
            }
            out.add(readCase(json, cursor));
        }
        return out;
    }

    private static Case readCase(String json, int[] cursor) {
        Case c = new Case();
        expect(json, cursor, '{');
        while (true) {
            skipSpace(json, cursor);
            char ch = json.charAt(cursor[0]);
            if (ch == '}') {
                cursor[0]++;
                return c;
            }
            if (ch == ',') {
                cursor[0]++;
                continue;
            }
            String field = readString(json, cursor);
            skipSpace(json, cursor);
            expect(json, cursor, ':');
            skipSpace(json, cursor);
            if (json.charAt(cursor[0]) == '[') {
                List<String> items = readStringArray(json, cursor);
                if (field.equals("secrets")) {
                    c.secrets = items;
                }
            } else {
                String value = readString(json, cursor);
                switch (field) {
                    case "name": c.name = value; break;
                    case "text": c.text = value; break;
                    case "nhiId": c.nhiId = value; break;
                    case "serviceAccount": c.serviceAccount = value; break;
                    default: break;
                }
            }
        }
    }

    private static List<String> readStringArray(String json, int[] cursor) {
        expect(json, cursor, '[');
        List<String> out = new ArrayList<>();
        while (true) {
            skipSpace(json, cursor);
            char ch = json.charAt(cursor[0]);
            if (ch == ']') {
                cursor[0]++;
                return out;
            }
            if (ch == ',') {
                cursor[0]++;
                continue;
            }
            out.add(readString(json, cursor));
        }
    }

    private static String readString(String json, int[] cursor) {
        skipSpace(json, cursor);
        expect(json, cursor, '"');
        StringBuilder sb = new StringBuilder();
        while (true) {
            char ch = json.charAt(cursor[0]++);
            if (ch == '"') {
                return sb.toString();
            }
            if (ch != '\\') {
                sb.append(ch);
                continue;
            }
            char esc = json.charAt(cursor[0]++);
            switch (esc) {
                case 'n': sb.append('\n'); break;
                case 't': sb.append('\t'); break;
                case 'r': sb.append('\r'); break;
                case 'b': sb.append('\b'); break;
                case 'f': sb.append('\f'); break;
                case '"': sb.append('"'); break;
                case '\\': sb.append('\\'); break;
                case '/': sb.append('/'); break;
                case 'u':
                    sb.append((char) Integer.parseInt(json.substring(cursor[0], cursor[0] + 4), 16));
                    cursor[0] += 4;
                    break;
                default:
                    throw new IllegalStateException("unsupported escape \\" + esc);
            }
        }
    }

    private static void expect(String json, int[] cursor, char want) {
        skipSpace(json, cursor);
        char got = json.charAt(cursor[0]);
        if (got != want) {
            throw new IllegalStateException("expected " + want + " but found " + got
                + " at " + cursor[0]);
        }
        cursor[0]++;
    }

    private static void skipSpace(String json, int[] cursor) {
        while (cursor[0] < json.length() && Character.isWhitespace(json.charAt(cursor[0]))) {
            cursor[0]++;
        }
    }

    private static void check(String what, boolean ok) {
        System.out.println((ok ? "ok   " : "FAIL ") + what);
        if (!ok) {
            failures++;
        }
    }

    private static void fail(String message) {
        System.out.println("  " + message);
        failures++;
    }
}
