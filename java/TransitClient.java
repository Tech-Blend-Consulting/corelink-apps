import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;

/**
 * Transit API client for Tech Blend Secrets Management.
 *
 * Authentication is via NHI (Non-Human Identity) passwordless attestation.
 * Call nhiConnect() before making any secret requests. A background scheduler
 * renews the session every 50 minutes automatically.
 *
 * Requires JDK 11+. No external dependencies.
 *
 * Usage:
 *   var client = new TransitClient("http://127.0.0.1:9090", "https://platform.example.com", "nhi_...");
 *   client.nhiConnect();
 *   var dbPass = client.getSecret("DB_PASSWORD");
 *   client.close();
 */
public class TransitClient implements AutoCloseable {

    private final String url;
    private final String platformUrl;
    private final String nhiId;
    private final HttpClient httpClient;
    private volatile String sessionId;
    private final AttestSupplier attest;

    /** Supplies {type, evidence} for a workload the SDK cannot recognise. */
    @FunctionalInterface
    public interface AttestSupplier {
        String[] get() throws Exception;
    }
    private ScheduledExecutorService scheduler;

    /** Construct a TransitClient for NHI passwordless authentication. */
    public TransitClient(String transitUrl, String platformUrl, String nhiId) {
        this(transitUrl, platformUrl, nhiId, null);
    }

    /**
     * As above, with an attestation supplied by the caller instead of detected.
     *
     * <p>For a workload that runs nowhere the SDK can recognise -- a product with no connector, no
     * pod and no instance identity document -- and federates to its own OIDC issuer instead. Return
     * {@code new String[]{"oidc", token}}.
     *
     * <p>A supplier rather than a string, because these tokens are short lived by design: it is
     * called on every connect and reconnect, so a session that drops at three in the morning
     * re-mints rather than replaying something that expired hours ago.
     *
     * <p>Nothing it returns authorises anything: CoreLink verifies the token against the issuer
     * pinned to this identity, and the grant decides what the identity may do.
     */
    public TransitClient(String transitUrl, String platformUrl, String nhiId, AttestSupplier attest) {
        this.url = transitUrl.replaceAll("/+$", "");
        this.platformUrl = platformUrl.replaceAll("/+$", "");
        this.nhiId = nhiId;
        this.attest = attest;
        this.httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5))
            .build();
    }

    /**
     * Connect to the platform using the NHI fingerprint.
     * Must be called before making secret requests.
     * Starts a background heartbeat on success.
     */
    public void nhiConnect() throws Exception {
        // evidence must not be logged -- it may contain a Kubernetes SA token.
        String[] attest = collectAttestation();
        String body = String.format(
            "{\"nhi_id\":\"%s\",\"attestation\":{\"type\":\"%s\",\"evidence\":\"%s\"}}",
            escapeJson(nhiId), attest[0], escapeJson(attest[1]));
        HttpRequest req = HttpRequest.newBuilder()
            .uri(URI.create(platformUrl + "/api/v1/nhi-agent/connect"))
            .timeout(Duration.ofSeconds(10))
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(body))
            .build();
        HttpResponse<String> resp = httpClient.send(req, HttpResponse.BodyHandlers.ofString());
        if (resp.statusCode() == 403) throw new RuntimeException("NHI identity verification failed");
        if (resp.statusCode() != 200) throw new RuntimeException("NHI connect failed: HTTP " + resp.statusCode());
        String sid = extractJsonString(resp.body(), "session_id");

        // Treat a missing status field as "active" for backward compatibility.
        String status = extractJsonString(resp.body(), "status");
        if (status == null || status.isEmpty()) status = "active";

        if (status.equals("pending_approval")) {
            String prefix = sid != null && sid.length() > 8 ? sid.substring(0, 8) : sid;
            System.out.printf("Waiting for admin approval (session: %s)...%n", prefix);
            pollApproval(sid);
        } else if (!status.equals("active")) {
            throw new RuntimeException("NHI connect returned unexpected status: " + status);
        }

        sessionId = sid;
        scheduleHeartbeat();
    }

    /**
     * Poll the platform every 5 seconds until the session is approved or rejected.
     * Times out after 5 minutes (60 attempts).
     */
    private void pollApproval(String sid) throws Exception {
        String url = platformUrl + "/api/v1/nhi-agent/connect/" + sid + "/status";
        for (int i = 0; i < 60; i++) {
            Thread.sleep(5000);
            try {
                HttpRequest req = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .timeout(Duration.ofSeconds(10))
                    .GET()
                    .build();
                HttpResponse<String> resp = httpClient.send(req, HttpResponse.BodyHandlers.ofString());
                if (resp.statusCode() == 200) {
                    String status = extractJsonString(resp.body(), "status");
                    if ("active".equals(status)) return;
                    if ("rejected".equals(status)) throw new RuntimeException("Connect request rejected by admin");
                }
            } catch (RuntimeException e) {
                throw e;
            } catch (Exception ignored) {
                // transient error; keep polling
            }
        }
        throw new RuntimeException("Approval timeout (5 minutes)");
    }

    /**
     * The secrets available to this client.
     *
     * <p>A connector serves envelopes by name and offers no way to enumerate them: an application
     * asks for what it was configured to ask for. There is nothing to list, so this throws rather
     * than returning an empty list that would read as "no secrets".
     */
    public List<Map<String, String>> listSecrets() throws Exception {
        throw new UnsupportedOperationException(
            "a connector serves envelopes by name and offers no listing; "
                + "name the secrets this application needs");
    }

    /**
     * The value of a single secret by name.
     *
     * <p>Takes the sealed envelope from the connector, asks CoreLink for the key to that secret,
     * and opens it here. The connector cannot read what it served and CoreLink never sees the
     * plaintext, so the value exists in this process and nowhere else.
     *
     * <p>It used to ask the connector for plaintext. That endpoint answers 410 now, and this goes
     * the sealed way instead, so an application already calling getSecret needs no change.
     */
    public String getSecret(String name) throws Exception {
        return getSecretSealed(name);
    }

    /**
     * Open a secret from a sealed envelope. See {@link #getSecret}.
     *
     * <p>Requires {@code secrets:unwrap} on the secret, and a connector granted
     * {@code secrets:cache} on it.
     *
     * <p>A stale envelope is retried once with the connector told to refetch, which is the case
     * this exists for: the connector holding a version CoreLink has since rotated past. A second
     * failure of the same kind is reported as stale rather than retried forever.
     */
    public String getSecretSealed(String name) throws Exception {
        if (url == null || url.isEmpty()) {
            throw new IllegalStateException("getSecretSealed needs a connector; set transitUrl");
        }
        if (platformUrl == null || platformUrl.isEmpty() || nhiId == null || nhiId.isEmpty()) {
            throw new IllegalStateException("getSecretSealed needs an identity; set platformUrl and nhiId");
        }
        try {
            return openSealed(name, false);
        } catch (Sealed.StaleEnvelope e) {
            return openSealed(name, true);
        }
    }

    /**
     * A TLS bundle, fetched through the sealed path and parsed here.
     *
     * <p>A certificate is a secret whose value is a bundle, so it needs no delivery mechanism of
     * its own: the same envelope, the same key, the same binding. The connector used to serve a
     * bundle's parts from plaintext it held in memory, which was the last readable thing in that
     * process.
     *
     * <p>The private key exists in this process and nowhere else.
     */
    public Sealed.Certificate getCertificate(String name) throws Exception {
        return Sealed.certificateFrom(getSecretSealed(name));
    }

    /**
     * Ask CoreLink for a credential leased for a while.
     *
     * <p>resourceType is one of {@link Leases#RESOURCE_SECRET}, {@code RESOURCE_DATABASE} or
     * {@code RESOURCE_CLOUD}. A zero ttlSeconds takes CoreLink's default; asking for longer than
     * policy allows is CoreLink's decision, and the lease says what was actually granted.
     */
    public Leases.Lease requestCredential(String resourceType, String resourceId, int ttlSeconds)
            throws Exception {
        if (platformUrl == null || platformUrl.isEmpty() || nhiId == null || nhiId.isEmpty()) {
            throw new IllegalStateException("requestCredential needs an identity; set platformUrl and nhiId");
        }
        if (!Leases.RESOURCE_TYPES.contains(resourceType)) {
            throw new IllegalArgumentException(
                    "resource type " + resourceType + " is not one of " + Leases.RESOURCE_TYPES);
        }
        if (resourceId == null || resourceId.isEmpty()) {
            throw new IllegalArgumentException("a resource id is required");
        }

        StringBuilder body = new StringBuilder();
        body.append("{\"resource_type\":\"").append(resourceType)
            .append("\",\"resource_id\":\"").append(resourceId).append("\"");
        if (ttlSeconds > 0) {
            body.append(",\"ttl_seconds\":").append(ttlSeconds);
        }
        body.append("}");

        HttpResponse<String> resp = platformRequest("POST", "/api/v1/nhi-agent/credentials", body.toString());
        if (resp.statusCode() != 200) {
            throw new RuntimeException("CoreLink refused to issue a credential: HTTP " + resp.statusCode());
        }
        Leases.Lease lease = Leases.fromJson(resp.body());
        if (lease.id.isEmpty()) {
            throw new RuntimeException("CoreLink issued a credential with no lease id");
        }
        return lease;
    }

    /**
     * Extend a lease, or say why it will not extend.
     *
     * <p>Throws {@link Leases.LeaseExhausted} at the credential's maximum lifetime. That is not a
     * failure to retry: request a new credential.
     */
    public void renewLease(String leaseId) throws Exception {
        if (leaseId == null || leaseId.isEmpty()) {
            throw new IllegalArgumentException("a lease id is required");
        }
        HttpResponse<String> resp = platformRequest(
                "POST",
                "/api/v1/nhi-agent/leases/" + java.net.URLEncoder.encode(leaseId, java.nio.charset.StandardCharsets.UTF_8) + "/renew",
                "");
        switch (resp.statusCode()) {
            case 200:
                return;
            case 422:
                throw new Leases.LeaseExhausted("this credential cannot be extended further");
            case 404:
                throw new Leases.LeaseNotFound("lease not found");
            default:
                throw new RuntimeException("renewing the lease failed: HTTP " + resp.statusCode());
        }
    }

    /**
     * Hand a credential back before it expires.
     *
     * <p>Worth doing rather than letting it lapse: it stops working at once. A lease already gone is
     * not an error, because the caller's intent is satisfied either way.
     */
    public void releaseCredential(String leaseId) throws Exception {
        if (leaseId == null || leaseId.isEmpty()) {
            throw new IllegalArgumentException("a lease id is required");
        }
        HttpResponse<String> resp = platformRequest(
                "DELETE",
                "/api/v1/nhi-agent/credentials/" + java.net.URLEncoder.encode(leaseId, java.nio.charset.StandardCharsets.UTF_8),
                null);
        int code = resp.statusCode();
        if (code == 200 || code == 204 || code == 404) {
            return;
        }
        throw new RuntimeException("releasing the credential failed: HTTP " + code);
    }

    /**
     * The identity's active leases, without their credentials.
     *
     * <p>The material is handed over once, at issue.
     */
    public List<Leases.Lease> listLeases() throws Exception {
        HttpResponse<String> resp = platformRequest("GET", "/api/v1/nhi-agent/credentials", null);
        if (resp.statusCode() != 200) {
            throw new RuntimeException("listing leases failed: HTTP " + resp.statusCode());
        }
        // "data" is the key CoreLink sends. Split on object boundaries rather than
        // parsing, for the same reason the rest of this file does: no dependencies.
        List<Leases.Lease> out = new java.util.ArrayList<>();
        String body = resp.body();
        int at = body.indexOf("\"data\"");
        if (at < 0) {
            return out;
        }
        for (int i = body.indexOf('{', at); i >= 0; i = body.indexOf('{', i + 1)) {
            int end = body.indexOf('}', i);
            if (end < 0) {
                break;
            }
            out.add(Leases.fromJson(body.substring(i, end + 1)));
        }
        return out;
    }

    /**
     * Sets the session directly, for tests.
     *
     * <p>The lease calls need a session and attestation is not what they are testing. Package
     * visibility rather than public, so an application cannot reach past bootstrap.
     */
    void setSessionForTesting(String session) {
        this.sessionId = session;
    }

    /** Send an authenticated request to CoreLink. */
    private HttpResponse<String> platformRequest(String method, String path, String body)
            throws Exception {
        if (sessionId == null || sessionId.isEmpty()) {
            throw new IllegalStateException("no CoreLink session; call bootstrap first");
        }
        HttpRequest.Builder builder = HttpRequest.newBuilder()
                .uri(URI.create(platformUrl + path))
                .timeout(Duration.ofSeconds(10))
                .header("X-NHI-Session", sessionId);
        if (body == null) {
            builder.method(method, HttpRequest.BodyPublishers.noBody());
        } else {
            builder.header("Content-Type", "application/json")
                   .method(method, HttpRequest.BodyPublishers.ofString(body));
        }
        return httpClient.send(builder.build(), HttpResponse.BodyHandlers.ofString());
    }

    /** One attempt at fetching, unwrapping and opening. */
    private String openSealed(String name, boolean refresh) throws Exception {
        String envelopeUrl = url + "/v1/envelopes/" + Sealed.envelopePath(name);
        if (refresh) {
            envelopeUrl += "?refresh=1";
        }

        // Unauthenticated: the connector has nothing to decide, because what it serves cannot be
        // opened without a grant CoreLink checks.
        HttpResponse<String> resp = httpClient.send(
            HttpRequest.newBuilder().uri(URI.create(envelopeUrl)).timeout(Duration.ofSeconds(10)).GET().build(),
            HttpResponse.BodyHandlers.ofString());
        if (resp.statusCode() != 200) {
            throw new RuntimeException(
                "the connector has no envelope for " + name + ": HTTP " + resp.statusCode());
        }
        String body = resp.body();
        String secretId = extractJsonString(body, "secret_id");
        String envelope = extractJsonString(body, "envelope");
        int servedVersion = extractJsonInt(body, "version");
        if (secretId == null || envelope == null) {
            throw new RuntimeException("the connector served an incomplete envelope for " + name);
        }

        // CoreLink unwraps its own copy, so nothing this process holds takes part: an application
        // handed somebody else's ciphertext cannot have it opened by naming a secret it is
        // entitled to.
        if (sessionId == null || sessionId.isEmpty()) {
            throw new IllegalStateException("no CoreLink session; call bootstrap first");
        }
        HttpResponse<String> keyResp = httpClient.send(
            HttpRequest.newBuilder()
                .uri(URI.create(platformUrl + "/api/v1/nhi-agent/secrets/" + secretId + "/unwrap"))
                .timeout(Duration.ofSeconds(10))
                .header("X-NHI-Session", sessionId)
                .POST(HttpRequest.BodyPublishers.noBody())
                .build(),
            HttpResponse.BodyHandlers.ofString());
        if (keyResp.statusCode() != 200) {
            throw new RuntimeException("CoreLink refused to unwrap: HTTP " + keyResp.statusCode());
        }
        String dekB64 = extractJsonString(keyResp.body(), "dek");
        int keyVersion = extractJsonInt(keyResp.body(), "version");
        // The name is CoreLink's answer to "which secret is this id?", which only it can give.
        String authoritativeName = extractJsonString(keyResp.body(), "name");
        if (dekB64 == null || dekB64.isEmpty()) {
            throw new RuntimeException("CoreLink returned no key");
        }

        // The name CoreLink says this id belongs to must be the name that was asked for. See
        // Sealed.WrongSecret: the AAD binds an envelope to its own id and version, so a
        // substituted secret opens cleanly and only this comparison catches it.
        String asked = name.replaceAll("^/+", "").replaceAll("/+$", "");
        if (authoritativeName != null && !authoritativeName.isEmpty()
            && !authoritativeName.equals(asked)) {
            throw new Sealed.WrongSecret(
                "asked for " + asked + " and the connector answered with " + authoritativeName);
        }

        byte[] dek = java.util.Base64.getDecoder().decode(dekB64);

        try {
            // The key belongs to whatever version CoreLink currently holds. A different one means
            // this envelope is behind, and saying so is clearer than letting the AEAD fail for an
            // unexplained reason.
            if (keyVersion != servedVersion) {
                throw new Sealed.StaleEnvelope(
                    "the connector served version " + servedVersion + ", CoreLink is on " + keyVersion);
            }
            byte[] plaintext = Sealed.openEnvelope(envelope, dek, secretId, keyVersion);
            try {
                return Sealed.valueFrom(plaintext);
            } finally {
                java.util.Arrays.fill(plaintext, (byte) 0);
            }
        } finally {
            java.util.Arrays.fill(dek, (byte) 0);
        }
    }

    /** Stop background schedulers and send a best-effort disconnect. */
    @Override
    public void close() {
        if (scheduler != null) {
            scheduler.shutdownNow();
            scheduler = null;
        }
        if (nhiId != null && !nhiId.isEmpty() && sessionId != null) {
            try {
                HttpRequest req = HttpRequest.newBuilder()
                    .uri(URI.create(platformUrl + "/api/v1/nhi-agent/disconnect"))
                    .header("X-NHI-Session", sessionId)
                    .POST(HttpRequest.BodyPublishers.noBody())
                    .build();
                httpClient.send(req, HttpResponse.BodyHandlers.discarding());
            } catch (Exception ignored) {}
        }
    }

    // --- NHI internals ---

    /**
     * Auto-detect the runtime environment and return {attestType, evidence}.
     *
     * Detection order:
     *   1. Kubernetes: service account token projected by the kubelet.
     *   2. Host fallback: stable fingerprint derived from computeFingerprint().
     *
     * AWS, Azure, and GCP detection require HTTP calls to instance metadata
     * endpoints and are left as future work. The server accepts "host" for
     * non-cloud deployments.
     *
     * The returned evidence must never be logged -- it may contain a
     * Kubernetes service account JWT.
     */
    private String[] collectAttestation() throws Exception {
        // The caller first: a workload federating to its own issuer knows how to get its token and
        // the SDK does not; a pod or a host is the other way round.
        if (attest != null) {
            return attest.get();
        }
        return detectAttestation();
    }

    private String[] detectAttestation() throws Exception {
        // Kubernetes: service account token projected by the kubelet.
        try {
            String token = java.nio.file.Files.readString(
                java.nio.file.Paths.get("/var/run/secrets/kubernetes.io/serviceaccount/token")).trim();
            if (!token.isEmpty()) return new String[]{"kubernetes", token};
        } catch (Exception ignored) {}

        // Host fallback: use the stable fingerprint as evidence.
        String[] fp = computeFingerprint();
        return new String[]{"host", fp[0]};
    }

    /**
     * Compute the NHI fingerprint components.
     * Returns [fingerprint, binHashHex, machineId, hostname].
     * The fingerprint is not logged anywhere in this method.
     */
    private String[] computeFingerprint() throws Exception {
        java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");

        // Binary hash of the running JAR/class file
        String jarPath = TransitClient.class.getProtectionDomain().getCodeSource().getLocation().toURI().getPath();
        byte[] jarBytes = java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(jarPath));
        byte[] binHash = md.digest(jarBytes);
        String binHashHex = bytesToHex(binHash);

        // Machine ID: prefer /etc/machine-id on Linux, fall back to hostname
        String machineId = "";
        String os = System.getProperty("os.name", "").toLowerCase();
        if (os.contains("linux")) {
            try {
                machineId = java.nio.file.Files.readString(java.nio.file.Paths.get("/etc/machine-id")).trim();
            } catch (Exception e) {
                // fallback below
            }
        }
        if (machineId.isEmpty()) {
            machineId = java.net.InetAddress.getLocalHost().getHostName();
        }

        String hostname = java.net.InetAddress.getLocalHost().getHostName();

        // Combine: SHA-256(binHash || machineId || hostname || nhiId)
        md.reset();
        md.update(binHash);
        md.update(machineId.getBytes());
        md.update(hostname.getBytes());
        md.update(nhiId.getBytes());
        String fingerprint = bytesToHex(md.digest());

        return new String[]{fingerprint, binHashHex, machineId, hostname};
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    private void scheduleHeartbeat() {
        if (scheduler != null) scheduler.shutdownNow();
        scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "nhi-heartbeat");
            t.setDaemon(true);
            return t;
        });
        scheduler.scheduleAtFixedRate(() -> {
            try {
                nhiHeartbeat();
            } catch (Exception e) {
                try { nhiConnect(); } catch (Exception ex) { /* reconnect failed -- will retry next interval */ }
            }
        }, 50, 50, TimeUnit.MINUTES);
    }

    private void nhiHeartbeat() throws Exception {
        // evidence must not be logged -- it may contain a Kubernetes SA token.
        String[] attest = collectAttestation();
        String body = String.format(
            "{\"attestation\":{\"type\":\"%s\",\"evidence\":\"%s\"}}",
            attest[0], escapeJson(attest[1]));
        HttpRequest req = HttpRequest.newBuilder()
            .uri(URI.create(platformUrl + "/api/v1/nhi-agent/heartbeat"))
            .timeout(Duration.ofSeconds(10))
            .header("Content-Type", "application/json")
            .header("X-NHI-Session", sessionId)
            .POST(HttpRequest.BodyPublishers.ofString(body))
            .build();
        HttpResponse<String> resp = httpClient.send(req, HttpResponse.BodyHandlers.ofString());
        if (resp.statusCode() == 401 || resp.statusCode() == 403) {
            nhiConnect();
        }
    }

    // --- Auth / HTTP helpers ---

    private HttpResponse<String> authedGet(String targetUrl) throws Exception {
        HttpResponse<String> resp = doGet(targetUrl);
        if (resp.statusCode() == 401) {
            // Session expired: reconnect and retry once.
            nhiConnect();
            resp = doGet(targetUrl);
        }
        return resp;
    }

    private HttpResponse<String> doGet(String targetUrl) throws Exception {
        HttpRequest.Builder builder = HttpRequest.newBuilder()
            .uri(URI.create(targetUrl))
            .timeout(Duration.ofSeconds(5))
            .GET();
        if (sessionId != null && !sessionId.isEmpty()) {
            builder.header("X-NHI-Session", sessionId);
        }
        return httpClient.send(builder.build(), HttpResponse.BodyHandlers.ofString());
    }

    // --- Minimal JSON helpers (no external deps) ---

    /** Read one numeric field out of a flat JSON object. Returns -1 when absent. */
    static int extractJsonInt(String json, String key) {
        int idx = json.indexOf("\"" + key + "\"");
        if (idx < 0) return -1;
        int colon = json.indexOf(":", idx);
        if (colon < 0) return -1;
        int i = colon + 1;
        while (i < json.length() && Character.isWhitespace(json.charAt(i))) i++;
        int start = i;
        while (i < json.length() && (Character.isDigit(json.charAt(i)) || json.charAt(i) == '-')) i++;
        if (start == i) return -1;
        try {
            return Integer.parseInt(json.substring(start, i));
        } catch (NumberFormatException e) {
            return -1;
        }
    }

    static String extractJsonString(String json, String key) {
        int idx = json.indexOf("\"" + key + "\"");
        if (idx < 0) return null;
        int valStart = json.indexOf("\"", json.indexOf(":", idx) + 1);
        if (valStart < 0) return null;
        valStart++;
        StringBuilder sb = new StringBuilder();
        for (int i = valStart; i < json.length(); i++) {
            char c = json.charAt(i);
            if (c == '\\' && i + 1 < json.length()) {
                sb.append(json.charAt(++i));
            } else if (c == '"') {
                break;
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    static String extractJsonNumber(String json, String key) {
        int idx = json.indexOf("\"" + key + "\"");
        if (idx < 0) return null;
        int colon = json.indexOf(":", idx);
        if (colon < 0) return null;
        int start = colon + 1;
        while (start < json.length() && json.charAt(start) == ' ') start++;
        StringBuilder sb = new StringBuilder();
        for (int i = start; i < json.length(); i++) {
            char c = json.charAt(i);
            if (Character.isDigit(c) || c == '.' || c == '-') sb.append(c);
            else break;
        }
        return sb.length() > 0 ? sb.toString() : null;
    }

    static List<Map<String, String>> parseSecrets(String json) {
        List<Map<String, String>> result = new ArrayList<>();
        int idx = json.indexOf("\"secrets\"");
        if (idx < 0) return result;
        int arrStart = json.indexOf("[", idx);
        if (arrStart < 0) return result;
        int depth = 1;
        int objStart = -1;
        for (int i = arrStart + 1; i < json.length(); i++) {
            char c = json.charAt(i);
            if (c == '{') {
                if (depth == 1) objStart = i;
                depth++;
            } else if (c == '}') {
                depth--;
                if (depth == 1 && objStart >= 0) {
                    String obj = json.substring(objStart, i + 1);
                    String name = extractJsonString(obj, "name");
                    String value = extractJsonString(obj, "value");
                    if (name != null) {
                        Map<String, String> entry = new LinkedHashMap<>();
                        entry.put("name", name);
                        entry.put("value", value != null ? value : "");
                        result.add(entry);
                    }
                    objStart = -1;
                }
            } else if (c == ']' && depth == 1) {
                break;
            }
        }
        return result;
    }

    private static String escapeJson(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}
