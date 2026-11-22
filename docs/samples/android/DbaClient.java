package org.devicebasedauth.sample;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * A devicebasedauth.org device client for Android (API 26+) and any JVM.
 *
 * It uses only classes both have (java.security, HttpURLConnection, java.util.Base64), so the
 * same file runs in CI on a JVM and in an app with a key from the Android Keystore
 * ({@link AndroidKeystoreKeys}). The private key never leaves its {@link PrivateKey} object:
 * with the Keystore that means it never leaves the secure hardware.
 *
 * Steps: send an enrollment request signed by the device key (ES256 JWS, public key in the
 * header); show the approval link to the account owner; poll until approved; then sign a DPoP
 * proof for each request. Call these off the main thread: they block on the network.
 */
public final class DbaClient {
    /** Receives the link the account owner opens to approve this device. */
    public interface ApprovalListener {
        void onApprovalUrl(String url);
    }

    /** An error response from devicebasedauth.org ({ error, code }). */
    public static final class ApiException extends IOException {
        private static final long serialVersionUID = 1L;
        public final int status;
        public final String code;
        /** With code "use_dpop_nonce": the nonce to put in a new proof (RFC 9449 §8). */
        public final String dpopNonce;

        ApiException(int status, String code, String message, String dpopNonce) {
            super(message + " (" + code + ")");
            this.status = status;
            this.code = code;
            this.dpopNonce = dpopNonce;
        }
    }

    private static final SecureRandom RANDOM = new SecureRandom();
    private final String origin;
    private final PrivateKey privateKey;
    private final Map<String, Object> publicJwk;

    /**
     * @param origin     https://devicebasedauth.org (or a local server)
     * @param privateKey the device's P-256 private key; an Android Keystore key works as is
     * @param publicKey  its public half
     */
    public DbaClient(String origin, PrivateKey privateKey, ECPublicKey publicKey) {
        this.origin = origin.replaceAll("/+$", "");
        this.privateKey = privateKey;
        this.publicJwk = publicJwk(publicKey);
    }

    /**
     * Ask for a credential and wait for the account owner to approve it.
     *
     * @param audiences     sites the credential is for, e.g. ["hashbin.org"]
     * @param grants        what the device may do, e.g. [{"actions": ["hashbin:content:write"]}]
     * @param device        {name, kind, key_protection} shown to the approver
     * @return the credential (a compact JWS); store it with the key alias, it is not secret
     */
    public String enroll(List<String> audiences, List<Object> grants, Map<String, Object> device, ApprovalListener listener)
            throws IOException, GeneralSecurityException, InterruptedException {
        return enroll(audiences, grants, device, null, listener);
    }

    /**
     * As above, with key attestation: {@code attestation} is
     * {@link AndroidKeystoreKeys#attestation(String)} for a key created with a challenge from
     * {@link #attestationChallenge(String)}. A rejected attestation fails the enrollment
     * (ApiException code invalid_attestation) rather than enrolling unattested.
     */
    public String enroll(List<String> audiences, List<Object> grants, Map<String, Object> device, Map<String, Object> attestation, ApprovalListener listener)
            throws IOException, GeneralSecurityException, InterruptedException {
        Map<String, Object> header = map("typ", "dba-enroll+jwt", "jwk", publicJwk);
        Map<String, Object> payload = map("iat", now(), "aud", audiences, "grants", grants, "device", device);
        if (attestation != null) payload.put("attestation", attestation);
        Map<String, Object> start = asMap(send("POST", origin + "/api/v1/enrollments", map("request", signJws(header, payload)), null));
        listener.onApprovalUrl((String) start.get("approval_url"));

        long deadline = System.currentTimeMillis() + 1000L * ((Number) start.get("expires_in")).longValue();
        long interval = ((Number) start.get("interval")).longValue();
        while (System.currentTimeMillis() < deadline) {
            Thread.sleep(1000L * interval);
            Map<String, Object> poll = asMap(send("GET", (String) start.get("poll_url"), null, null));
            String status = (String) poll.get("status");
            if ("approved".equals(status)) return (String) poll.get("credential");
            if (!"pending".equals(status)) throw new IOException("Enrollment " + status);
            if (poll.get("interval") instanceof Number) interval = ((Number) poll.get("interval")).longValue();
        }
        throw new IOException("Gave up waiting for approval");
    }

    /** A key attestation challenge (valid 10 minutes), to create the Keystore key with. */
    public static String attestationChallenge(String origin) throws IOException {
        Map<String, Object> body = asMap(send("POST", origin.replaceAll("/+$", "") + "/api/v1/enrollments/attestation-challenge", map(), null));
        return (String) body.get("challenge");
    }

    /**
     * Call an API with the credential: Authorization: DBA <credential> plus a fresh DPoP proof. An
     * account object that started less than a minute ago answers 401 use_dpop_nonce with its nonce:
     * the request is sent once more with it, and the nonce is kept for later proofs.
     */
    public Object call(String method, String url, String credential, Object body) throws IOException, GeneralSecurityException {
        try {
            return send(method, url, body, authHeaders(credential, method, url));
        } catch (ApiException e) {
            if (!"use_dpop_nonce".equals(e.code) || e.dpopNonce == null || e.dpopNonce.equals(dpopNonce)) throw e;
            dpopNonce = e.dpopNonce;
            return send(method, url, body, authHeaders(credential, method, url));
        }
    }

    private Map<String, String> authHeaders(String credential, String method, String url) throws GeneralSecurityException {
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("Authorization", "DBA " + credential);
        headers.put("DPoP", dpopProof(credential, method, url));
        return headers;
    }

    /** The latest DPoP nonce devicebasedauth.org handed out, put in every later proof. */
    private volatile String dpopNonce;

    /** A single-use proof bound to this method, URL (without query or fragment) and credential (ath). */
    public String dpopProof(String credential, String method, String url) throws GeneralSecurityException {
        String htu = url.split("[?#]", 2)[0];
        byte[] jti = new byte[16];
        RANDOM.nextBytes(jti);
        byte[] ath = MessageDigest.getInstance("SHA-256").digest(credential.getBytes(StandardCharsets.US_ASCII));
        Map<String, Object> payload = map("jti", b64u(jti), "htm", method.toUpperCase(java.util.Locale.ROOT), "htu", htu, "iat", now(), "ath", b64u(ath));
        String nonce = dpopNonce;
        if (nonce != null) payload.put("nonce", nonce);
        return signJws(map("typ", "dpop+jwt", "jwk", publicJwk), payload);
    }

    /** Compact JWS with ES256. Java returns a DER signature; JOSE wants raw r || s. */
    String signJws(Map<String, Object> header, Map<String, Object> payload) throws GeneralSecurityException {
        Map<String, Object> h = new LinkedHashMap<>(header);
        h.put("alg", "ES256");
        String input = b64u(Json.write(h).getBytes(StandardCharsets.UTF_8)) + "." + b64u(Json.write(payload).getBytes(StandardCharsets.UTF_8));
        Signature signer = Signature.getInstance("SHA256withECDSA");
        signer.initSign(privateKey);
        signer.update(input.getBytes(StandardCharsets.US_ASCII));
        return input + "." + b64u(derToRaw(signer.sign()));
    }

    /** The public JWK the server stores and binds the credential to (cnf.jkt is its thumbprint). */
    static Map<String, Object> publicJwk(ECPublicKey key) {
        return map("kty", "EC", "crv", "P-256", "x", b64u(fixed32(key.getW().getAffineX())), "y", b64u(fixed32(key.getW().getAffineY())));
    }

    /** DER SEQUENCE { INTEGER r, INTEGER s } to 64 bytes r || s. */
    static byte[] derToRaw(byte[] der) {
        int offset = 2;
        if ((der[1] & 0x80) != 0) offset += der[1] & 0x7f; // long-form length (not used by P-256)
        int rLength = der[offset + 1];
        BigInteger r = new BigInteger(1, java.util.Arrays.copyOfRange(der, offset + 2, offset + 2 + rLength));
        offset += 2 + rLength;
        int sLength = der[offset + 1];
        BigInteger s = new BigInteger(1, java.util.Arrays.copyOfRange(der, offset + 2, offset + 2 + sLength));
        byte[] raw = new byte[64];
        System.arraycopy(fixed32(r), 0, raw, 0, 32);
        System.arraycopy(fixed32(s), 0, raw, 32, 32);
        return raw;
    }

    private static byte[] fixed32(BigInteger value) {
        byte[] bytes = value.toByteArray(); // may carry a leading 0 sign byte, or be short
        byte[] out = new byte[32];
        int copy = Math.min(32, bytes.length);
        System.arraycopy(bytes, bytes.length - copy, out, 32 - copy, copy);
        return out;
    }

    private static Object send(String method, String url, Object body, Map<String, String> headers) throws IOException {
        HttpURLConnection connection = (HttpURLConnection) new URL(url).openConnection();
        connection.setRequestMethod(method);
        connection.setConnectTimeout(30_000);
        connection.setReadTimeout(30_000);
        connection.setRequestProperty("Accept", "application/json");
        if (headers != null) for (Map.Entry<String, String> h : headers.entrySet()) connection.setRequestProperty(h.getKey(), h.getValue());
        if (body != null) {
            connection.setDoOutput(true);
            connection.setRequestProperty("Content-Type", "application/json");
            try (OutputStream out = connection.getOutputStream()) {
                out.write(Json.write(body).getBytes(StandardCharsets.UTF_8));
            }
        }
        int status = connection.getResponseCode();
        InputStream stream = status >= 400 ? connection.getErrorStream() : connection.getInputStream();
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        if (stream != null) try (InputStream in = stream) {
            byte[] chunk = new byte[8192];
            for (int n; (n = in.read(chunk)) > 0; ) buffer.write(chunk, 0, n);
        }
        Object json = Json.parse(new String(buffer.toByteArray(), StandardCharsets.UTF_8));
        if (status >= 400) {
            Map<String, Object> error = json instanceof Map ? asMap(json) : map();
            Object nonce = error.get("dpop_nonce");
            throw new ApiException(status, String.valueOf(error.get("code")), method + " " + url + ": " + error.get("error"), nonce instanceof String ? (String) nonce : null);
        }
        return json;
    }

    static String b64u(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static long now() {
        return System.currentTimeMillis() / 1000;
    }

    /** An insertion-ordered map from alternating keys and values. */
    public static Map<String, Object> map(Object... pairs) {
        Map<String, Object> out = new LinkedHashMap<>();
        for (int i = 0; i < pairs.length; i += 2) out.put((String) pairs[i], pairs[i + 1]);
        return out;
    }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> asMap(Object value) {
        return (Map<String, Object>) value;
    }

    /**
     * Just enough JSON for this API, so the sample has no dependencies. In an app, org.json or
     * your usual library does the same job.
     */
    public static final class Json {
        private final String text;
        private int at;

        private Json(String text) {
            this.text = text;
        }

        public static String write(Object value) {
            StringBuilder out = new StringBuilder();
            write(value, out);
            return out.toString();
        }

        private static void write(Object value, StringBuilder out) {
            if (value == null) out.append("null");
            else if (value instanceof String) quote((String) value, out);
            else if (value instanceof Number || value instanceof Boolean) out.append(value);
            else if (value instanceof Map) {
                out.append('{');
                boolean first = true;
                for (Map.Entry<?, ?> e : ((Map<?, ?>) value).entrySet()) {
                    if (!first) out.append(',');
                    first = false;
                    quote((String) e.getKey(), out);
                    out.append(':');
                    write(e.getValue(), out);
                }
                out.append('}');
            } else if (value instanceof List) {
                out.append('[');
                List<?> list = (List<?>) value;
                for (int i = 0; i < list.size(); i++) {
                    if (i > 0) out.append(',');
                    write(list.get(i), out);
                }
                out.append(']');
            } else throw new IllegalArgumentException("cannot write " + value.getClass());
        }

        private static void quote(String s, StringBuilder out) {
            out.append('"');
            for (int i = 0; i < s.length(); i++) {
                char c = s.charAt(i);
                if (c == '"' || c == '\\') out.append('\\').append(c);
                else if (c < 0x20) out.append(String.format("\\u%04x", (int) c));
                else out.append(c);
            }
            out.append('"');
        }

        public static Object parse(String text) {
            Json parser = new Json(text);
            Object value = parser.value();
            parser.space();
            if (parser.at != text.length()) throw new IllegalArgumentException("trailing JSON");
            return value;
        }

        private void space() {
            while (at < text.length() && Character.isWhitespace(text.charAt(at))) at++;
        }

        private Object value() {
            space();
            if (at >= text.length()) throw new IllegalArgumentException("unexpected end of JSON");
            char c = text.charAt(at);
            if (c == '{') {
                Map<String, Object> out = new LinkedHashMap<>();
                at++;
                space();
                if (text.charAt(at) == '}') { at++; return out; }
                while (true) {
                    space();
                    String key = string();
                    space();
                    expect(':');
                    out.put(key, value());
                    space();
                    if (text.charAt(at++) == '}') return out;
                }
            }
            if (c == '[') {
                List<Object> out = new ArrayList<>();
                at++;
                space();
                if (text.charAt(at) == ']') { at++; return out; }
                while (true) {
                    out.add(value());
                    space();
                    if (text.charAt(at++) == ']') return out;
                }
            }
            if (c == '"') return string();
            if (text.startsWith("true", at)) { at += 4; return Boolean.TRUE; }
            if (text.startsWith("false", at)) { at += 5; return Boolean.FALSE; }
            if (text.startsWith("null", at)) { at += 4; return null; }
            int start = at;
            while (at < text.length() && "+-0123456789.eE".indexOf(text.charAt(at)) >= 0) at++;
            if (start == at) throw new IllegalArgumentException("bad JSON at " + at);
            return Double.valueOf(text.substring(start, at));
        }

        private String string() {
            expect('"');
            StringBuilder out = new StringBuilder();
            while (true) {
                char c = text.charAt(at++);
                if (c == '"') return out.toString();
                if (c != '\\') { out.append(c); continue; }
                char e = text.charAt(at++);
                switch (e) {
                    case 'n': out.append('\n'); break;
                    case 't': out.append('\t'); break;
                    case 'r': out.append('\r'); break;
                    case 'b': out.append('\b'); break;
                    case 'f': out.append('\f'); break;
                    case 'u': out.append((char) Integer.parseInt(text.substring(at, at + 4), 16)); at += 4; break;
                    default: out.append(e);
                }
            }
        }

        private void expect(char c) {
            if (text.charAt(at++) != c) throw new IllegalArgumentException("expected " + c + " at " + (at - 1));
        }
    }
}
