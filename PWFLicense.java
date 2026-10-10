// PWFKeys SDK v2.0  ·  build 1mif1w3  ·  java  ·  app 43a3d87a-9b18-4619-9094-38aef76e615e  ·  generated 2026-10-09 UTC
// Auto-generated — regenerate from the SDK Generator instead of editing by hand.

// Requires: org.json  (https://mvnrepository.com/artifact/org.json/json)
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.json.JSONObject;

public class PWFLicense {

    // AES-256-CBC envelope encryption — mirrors the server's PayloadCrypto.
    static class CryptoEnvelope {
        private final byte[] encKey;
        private final byte[] macKey;
        private static final int MAX_DRIFT = 300; // keep in sync with the server

        // Seconds added to this machine's clock so our timestamps match the server's. Set from
        // the server's own time when it refuses a request as CLOCK_SKEW (a wrong system clock).
        private volatile long clockOffset = 0;

        long now() { return System.currentTimeMillis() / 1000L + clockOffset; }

        // True when the reply is the server's CLOCK_SKEW refusal: the offset is then set from
        // its server_time, and the caller sends the request once more.
        boolean adjustClock(JSONObject reply) {
            if (reply == null || !"CLOCK_SKEW".equals(reply.optString("reason"))) return false;
            long serverTime = reply.optLong("server_time", 0L);
            if (serverTime <= 0) return false;
            clockOffset = serverTime - System.currentTimeMillis() / 1000L;
            return true;
        }

        CryptoEnvelope(String appSecret) throws Exception {
            MessageDigest sha = MessageDigest.getInstance("SHA-256");
            encKey = sha.digest(("enc:" + appSecret).getBytes(StandardCharsets.UTF_8));
            sha.reset();
            macKey = sha.digest(("mac:" + appSecret).getBytes(StandardCharsets.UTF_8));
        }

        String encrypt(JSONObject data) throws Exception {
            byte[] iv = new byte[16];
            new SecureRandom().nextBytes(iv);

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(encKey, "AES"), new IvParameterSpec(iv));
            byte[] ct = cipher.doFinal(data.toString().getBytes(StandardCharsets.UTF_8));

            byte[] combined = new byte[iv.length + ct.length];
            System.arraycopy(iv, 0, combined, 0, iv.length);
            System.arraycopy(ct, 0, combined, iv.length, ct.length);

            String p = Base64.getEncoder().encodeToString(combined);
            long t = now();
            String s = hmacHex(p + t);

            return new JSONObject().put("p", p).put("t", t).put("s", s).toString();
        }

        JSONObject decrypt(String envelopeJson) throws Exception {
            JSONObject env = new JSONObject(envelopeJson);
            if (!env.has("p") || !env.has("t") || !env.has("s"))
                throw new Exception("Invalid envelope format");

            String p = env.getString("p");
            long t = env.getLong("t");
            String s = env.getString("s");

            if (!hmacHex(p + t).equalsIgnoreCase(s))
                throw new Exception("HMAC verification failed");

            if (Math.abs(now() - t) > MAX_DRIFT)
                throw new Exception("Request expired (replay protection) - check the system clock");

            byte[] combined = Base64.getDecoder().decode(p);
            byte[] iv = new byte[16];
            byte[] ct = new byte[combined.length - 16];
            System.arraycopy(combined, 0, iv, 0, 16);
            System.arraycopy(combined, 16, ct, 0, ct.length);

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(encKey, "AES"), new IvParameterSpec(iv));
            byte[] plain = cipher.doFinal(ct);
            return new JSONObject(new String(plain, StandardCharsets.UTF_8));
        }

        private String hmacHex(String msg) throws Exception {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(macKey, "HmacSHA256"));
            byte[] h = mac.doFinal(msg.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : h) sb.append(String.format("%02x", b));
            return sb.toString();
        }
    }

    private final String baseUrl = "https://pwfauth.com";
    private final String appSecret = System.getenv("PWF_APP_SECRET");
    private final CryptoEnvelope crypto;
    private final HttpClient http = HttpClient.newHttpClient();
    private String sessionId;
    private String licenseKey;
    private int heartbeatInterval = 30; // seconds; overwritten from the login response

    public PWFLicense() throws Exception {
        crypto = new CryptoEnvelope(appSecret);
    }

    // Stable per-machine id. Windows goes through CIM — wmic was deprecated and is
    // GONE from Windows 11 24H2, so anything built on it silently degrades.
    public String getHWID() {
        boolean win = System.getProperty("os.name", "").toLowerCase().contains("win");
        String fallback = win ? System.getenv("COMPUTERNAME") : System.getenv("HOSTNAME");
        if (fallback == null || fallback.isEmpty()) fallback = "unknown-hwid";
        try {
            if (win) {
                Process proc = new ProcessBuilder("powershell", "-NoProfile", "-Command",
                    "(Get-CimInstance Win32_BaseBoard).SerialNumber").start();
                java.util.Scanner sc = new java.util.Scanner(proc.getInputStream());
                String line = sc.hasNextLine() ? sc.nextLine().trim() : "";
                sc.close();
                return line.isEmpty() ? fallback : line;
            }
            String id = new String(java.nio.file.Files.readAllBytes(
                java.nio.file.Paths.get("/etc/machine-id"))).trim();
            return id.isEmpty() ? fallback : id;
        } catch (Exception e) {
            return fallback;
        }
    }

    // Shared reply handler for every transport. Surfaces HTTP/transport failures
    // with a readable message instead of a cryptic JSON exception, then
    // transparently decrypts the body when the server enveloped it.
    private JSONObject parseReply(String raw, int status) throws Exception {
        if (raw == null || raw.trim().isEmpty())
            throw new Exception("License server returned HTTP " + status + " with an empty body.");
        JSONObject probe;
        try { probe = new JSONObject(raw); }
        catch (Exception e) {
            // Not JSON at all — usually a proxy/CDN error page or a wrong base URL.
            throw new Exception("License server returned HTTP " + status
                + " with a non-JSON body. Check the API base URL.");
        }
        if (probe.has("p") && probe.has("t") && probe.has("s"))
            return crypto.decrypt(raw);
        if (status >= 400 && !probe.has("success"))
            throw new Exception("License server returned HTTP " + status + ".");
        return probe; // plain server response (its own success/error_code shape)
    }

    // Encrypt the request, send it, and hand the reply to parseReply. On a wrong system
    // clock the server refuses the timestamp and sends its own time: adjustClock shifts
    // ours to match, and the request goes once more.
    private JSONObject post(String endpoint, JSONObject body) throws Exception {
        JSONObject reply = postOnce(endpoint, body);
        return crypto.adjustClock(reply) ? postOnce(endpoint, body) : reply;
    }

    private JSONObject postOnce(String endpoint, JSONObject body) throws Exception {
        String encrypted = crypto.encrypt(body);
        HttpRequest req = HttpRequest.newBuilder()
            .uri(URI.create(baseUrl + endpoint))
            .header("Content-Type", "application/json")
            .header("X-App-Secret", appSecret)
            .POST(HttpRequest.BodyPublishers.ofString(encrypted))
            .build();
        HttpResponse<String> res = http.send(req, HttpResponse.BodyHandlers.ofString());
        return parseReply(res.body(), res.statusCode());
    }

    // login.php also activates the key on first use — no separate activate call.
    public JSONObject login(String licenseKey) throws Exception {
        JSONObject body = new JSONObject()
            .put("license_key", licenseKey)
            .put("hwid", getHWID());
        JSONObject result = post("/api/auth/login.php", body);
        if (result.optBoolean("success", false)) {
            sessionId = result.optString("session_id", null);
            this.licenseKey = licenseKey;
            heartbeatInterval = result.optInt("heartbeat_interval", 30);
        }
        return result;
    }

    // Lightweight status + feature-map check WITHOUT opening a session
    // (no device seat is consumed) — handy before the user logs in.
    public JSONObject checkKey(String licenseKey) throws Exception {
        return post("/api/auth/check-key.php", new JSONObject().put("license_key", licenseKey));
    }

    public JSONObject heartbeat() throws Exception {
        if (sessionId == null) return null;
        return post("/api/auth/heartbeat.php", new JSONObject()
            .put("session_id", sessionId)
            .put("license_key", licenseKey));
    }

    // Blocking loop (run it on a background thread). Pings on the server interval and
    // REACTS to the kill switch: a ban / pause / expire / HWID-reset / revoke makes the
    // next heartbeat return success=false, and we call onRevoked(code, message) then stop.
    //
    // A single network blip is retried, but MAX_HEARTBEAT_FAILURES consecutive failures
    // also end the session with NETWORK_LOST — the server drops the session anyway, so
    // firewalling this domain must not leave a working app.
    private static final int MAX_HEARTBEAT_FAILURES = 3;

    public void runHeartbeat(java.util.function.BiConsumer<String, String> onRevoked) {
        java.util.List<String> kill = java.util.Arrays.asList(
            "BANNED", "PAUSED", "EXPIRED", "HWID_RESET", "MAINTENANCE",
            "SESSION_REVOKED", "SESSION_EXPIRED", "SESSION_MISMATCH");
        int failures = 0;
        while (sessionId != null) {
            try { Thread.sleep(heartbeatInterval * 1000L); }
            catch (InterruptedException e) { return; }
            JSONObject r = null;
            try { r = heartbeat(); }
            catch (Exception e) { r = null; }
            if (r == null) {
                if (sessionId == null) return;              // logged out meanwhile
                if (++failures >= MAX_HEARTBEAT_FAILURES) {
                    sessionId = null;
                    onRevoked.accept("NETWORK_LOST",
                        "Cannot reach the license server. Please check your connection and sign in again.");
                    return;
                }
                continue;                                    // transient — retry next tick
            }
            failures = 0;
            if (r.optBoolean("success", false)) continue;
            String code = r.optString("error_code", "");
            if (kill.contains(code)) {
                sessionId = null;                        // session is dead server-side
                onRevoked.accept(code, r.optString("message", ""));
                return;
            }
            // Unknown non-success: treat as transient and keep trying.
        }
    }

    // GET whose RESPONSE is enveloped. Pass the license key for Bearer endpoints.
    private JSONObject get(String endpoint, String bearerKey) throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder()
            .uri(URI.create(baseUrl + endpoint))
            .header("X-App-Secret", appSecret);
        if (bearerKey != null && !bearerKey.isEmpty()) b.header("Authorization", "Bearer " + bearerKey);
        HttpResponse<String> res = http.send(b.GET().build(), HttpResponse.BodyHandlers.ofString());
        return parseReply(res.body(), res.statusCode());
    }

    // POST plain JSON — endpoints that do NOT speak the envelope.
    private JSONObject postPlain(String endpoint, JSONObject body) throws Exception {
        HttpRequest req = HttpRequest.newBuilder()
            .uri(URI.create(baseUrl + endpoint))
            .header("Content-Type", "application/json")
            .header("X-App-Secret", appSecret)
            .POST(HttpRequest.BodyPublishers.ofString(body.toString()))
            .build();
        HttpResponse<String> res = http.send(req, HttpResponse.BodyHandlers.ofString());
        return parseReply(res.body(), res.statusCode());
    }

    // App metadata + social links + server "what's new" (name, version, download URL, maintenance flags).
    public JSONObject getAppInfo() throws Exception {
        return get("/api/app/info.php", null);
    }

    // Remote texts for THIS license (per-key overrides win over app defaults). Key rides in Authorization: Bearer.
    public JSONObject getTexts() throws Exception {
        return get("/api/app/text.php", licenseKey);
    }

    // Fetch the active promo / announcement slides configured for this app.
    public JSONObject getSlides() throws Exception {
        return post("/api/app/slides.php", new JSONObject().put("action", "get_slides"));
    }

    // Ask for a newer build on the stable channel. Returns update_available + version/sha256/download_url.
    public JSONObject checkUpdate(String currentVersion) throws Exception {
        return post("/api/update/check.php", new JSONObject().put("v", currentVersion).put("channel", "stable").put("hwid", getHWID()).put("license_key", licenseKey));
    }

    // Count a click on one of the app's social links (feeds the panel engagement stats).
    public JSONObject trackSocialClick(int linkId) throws Exception {
        return post("/api/app/social-click.php", new JSONObject().put("link_id", linkId));
    }

    // Mint a free trial key for this device. Off unless the owner enabled trials (else TRIAL_DISABLED / TRIAL_USED / TRIAL_LIMIT).
    public JSONObject createTrial() throws Exception {
        return postPlain("/api/auth/trial.php", new JSONObject().put("hwid", getHWID()));
    }

    // Self-service HWID reset: unbinds every device of the key right away so it can be activated on this PC. Call it when login fails with HWID_MISMATCH / DEVICE_LIMIT, then log in again. Follows the app's policy (App Settings): SELF_RESET_DISABLED when off, RATE_LIMITED inside the cooldown (12 h unless changed).
    public JSONObject resetHwid(String licenseKey, String reason) throws Exception {
        return postPlain("/api/customer/reset-hwid.php", new JSONObject().put("key", licenseKey).put("reason", reason));
    }

    // Queues a reset request for review. Requests are not shown in the dashboard yet, so nobody can approve them: use the self-service HWID reset above instead.
    public JSONObject requestHwidReset(String reason) throws Exception {
        return postPlain("/api/auth/request-hwid-reset.php", new JSONObject().put("license_key", licenseKey).put("reason", reason));
    }

    // Create an end-user account. Works while sign-up is on in App Settings > User Sign-up (on by default); the account gets the time set there.
    public JSONObject registerAccount(String username, String password, String email) throws Exception {
        return postPlain("/api/auth/account-register.php", new JSONObject().put("username", username).put("password", password).put("email", email));
    }

    // Create an account with a license key: the account gets the key's time and device limit, and the key is used up (it can no longer sign in on its own). Needed when App Settings > Account sign-up > "Sign-up needs a license key" is on (else KEY_REQUIRED). Refusals: INVALID_KEY, KEY_ALREADY_USED, KEY_IN_USE, BANNED, PAUSED, EXPIRED, USERNAME_EXISTS.
    public JSONObject registerAccountWithKey(String username, String password, String email, String licenseKey) throws Exception {
        return postPlain("/api/auth/account-register.php", new JSONObject().put("username", username).put("password", password).put("email", email).put("license_key", licenseKey));
    }

    // Add a license key's time to an existing account, also when it has expired (it cannot sign in then). App Settings decide whether the time goes on top of the time left or starts from now, and whether the account takes the key's device limit. Returns days_added, expires_at, days_remaining. Refusals: INVALID_CREDENTIALS, INVALID_KEY, KEY_ALREADY_USED, KEY_IN_USE, BANNED, PAUSED, ALREADY_LIFETIME.
    public JSONObject redeemKey(String username, String password, String licenseKey) throws Exception {
        return postPlain("/api/auth/account-redeem.php", new JSONObject().put("username", username).put("password", password).put("license_key", licenseKey));
    }

    // Sign an account in and open a session bound to this machine. Start the heartbeat afterwards, exactly as after a key login — the kill switch works the same way.
    public JSONObject loginAccount(String username, String password) throws Exception {
        JSONObject result = postPlain("/api/auth/account-login.php", new JSONObject().put("username", username).put("password", password).put("hwid", getHWID()));
        if (result.optBoolean("success", false)) {
            sessionId = result.optString("session_id", null);
            if (result.has("license_key")) licenseKey = result.optString("license_key", null);
        }
        return result;
    }

    // Change an end-user account password. The current password is required — this is not an admin reset.
    public JSONObject changeAccountPassword(String username, String currentPassword, String newPassword) throws Exception {
        return postPlain("/api/auth/change-password.php", new JSONObject().put("username", username).put("current_password", currentPassword).put("new_password", newPassword));
    }

    // Public price list — subscription levels and legacy plans for this app. No secret and no session needed, and the reply is plain JSON rather than enveloped.
    public JSONObject getPricing() throws Exception {
        return get("/api/app/pricing.php?app_id=43a3d87a-9b18-4619-9094-38aef76e615e", null);
    }

    public JSONObject logout() throws Exception {
        if (sessionId == null) return null;
        JSONObject result = post("/api/auth/logout.php", new JSONObject()
            .put("session_id", sessionId)
            .put("license_key", licenseKey));
        sessionId = null;
        return result;
    }
}

// Usage:
//   PWFLicense client = new PWFLicense();
//   JSONObject result = client.login("YOUR-LICENSE-KEY");
//   if (result.optBoolean("success")) {
//       JSONObject features = result.optJSONObject("features"); // entitlements from login
//       // Keep the session alive AND obey the admin kill switch (loops until revoked):
//       new Thread(() -> client.runHeartbeat((code, message) -> {
//           // code in {BANNED, PAUSED, EXPIRED, HWID_RESET, MAINTENANCE,
//           //          SESSION_REVOKED, SESSION_EXPIRED, SESSION_MISMATCH, NETWORK_LOST}
//           System.out.println("Session ended: " + code + " - " + message);
//           System.exit(0); // log the user out of YOUR app here
//       })).start();
//   }