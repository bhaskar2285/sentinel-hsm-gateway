package com.isc.sentinel.vendor.thales.command;

import com.isc.sentinel.vendor.thales.wire.HsmHeader;
import com.isc.sentinel.vendor.thales.wire.KeyScheme;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

/**
 * Phase-1 RESPONSE codec: parse + build for EJ, GJ, A9, M3.
 *
 * Mirrors {@link Phase1Builder} (request side). Each command pair (EI/EJ, GI/GJ, A8/A9, M2/M3)
 * has a request build/parse and a response parse/build, giving full symmetric wire codec.
 * Useful for audit replay, unit tests, wire-trace decoding and mock fixtures.
 *
 * Wire framing handled by caller — these helpers operate on the body that follows the
 * 2-byte length prefix and the echoed header.
 */
public final class Phase1Parser {

    private Phase1Parser() {}

    public record Parsed(String responseCode, String errorCode, Map<String, Object> fields) {}

    // =====================================================================
    // Top-level: dispatch on response code
    // =====================================================================

    /**
     * Parse a full Thales wire response: [echoed header][respCode(2)][errCode(2)][body...].
     */
    public static Parsed parse(byte[] wireBody, int headerLen, String expectedResponseCode) {
        String s = new String(wireBody, StandardCharsets.US_ASCII);
        if (s.length() < headerLen + 4) {
            throw new IllegalArgumentException("response too short: " + s.length());
        }
        int pos = headerLen;
        String respCode = s.substring(pos, pos + 2); pos += 2;
        String errCode  = s.substring(pos, pos + 2); pos += 2;

        if (!respCode.equals(expectedResponseCode)) {
            throw new IllegalStateException("unexpected response code: " + respCode
                + " (expected " + expectedResponseCode + ")");
        }

        Map<String, Object> fields = new HashMap<>();
        if (!"00".equals(errCode)) {
            return new Parsed(respCode, errCode, fields);
        }

        switch (respCode) {
            case "EJ" -> parseEJBody(s, pos, fields);
            case "GJ" -> parseGJBody(s, pos, fields);
            case "A1" -> parseA1Body(s, pos, fields);
            case "A7" -> parseA7Body(s, pos, fields);
            case "A9" -> parseA9Body(s, pos, fields);
            case "B5" -> parseB5Body(s, pos, fields);
            case "M1" -> parseM1Body(s, pos, fields);
            case "M3" -> parseM3Body(s, pos, fields);
            default   -> fields.put("raw", s.substring(pos));
        }
        return new Parsed(respCode, errCode, fields);
    }

    public static int headerLength(HsmHeader header) {
        return header.length();
    }

    // =====================================================================
    // EJ — RSA Key Pair Generate response
    // Body: PubKeyLen(4N) + PubKey(hex) + PrivKeyLen(4N) + PrivKey(hex, LMK-encrypted)
    // =====================================================================

    private static void parseEJBody(String s, int pos, Map<String, Object> f) {
        int pubLen = Integer.parseInt(s.substring(pos, pos + 4)); pos += 4;
        f.put("publicKey", s.substring(pos, pos + pubLen * 2)); pos += pubLen * 2;
        int privLen = Integer.parseInt(s.substring(pos, pos + 4)); pos += 4;
        f.put("privateKeyUnderLmk", s.substring(pos, pos + privLen * 2));
    }

    public static byte[] buildEJ(String errCode, Map<String, Object> fields) {
        if (!"00".equals(errCode)) return ("EJ" + errCode).getBytes(StandardCharsets.US_ASCII);
        String pub  = ((String) fields.get("publicKey")).toUpperCase();
        String priv = ((String) fields.get("privateKeyUnderLmk")).toUpperCase();
        String body = "EJ" + errCode
                    + String.format("%04d", pub.length()  / 2) + pub
                    + String.format("%04d", priv.length() / 2) + priv;
        return body.getBytes(StandardCharsets.US_ASCII);
    }

    // =====================================================================
    // GJ — Import Key under RSA response
    // Body: KeyType(3N) + Scheme(1A) + KeyUnderLmk(hex per scheme) + KCV(6H)
    // =====================================================================

    private static void parseGJBody(String s, int pos, Map<String, Object> f) {
        if (s.length() - pos < 3 + 1 + 6) { f.put("raw", s.substring(pos)); return; }
        f.put("keyType", s.substring(pos, pos + 3)); pos += 3;
        String scheme = s.substring(pos, pos + 1); pos += 1;
        f.put("scheme", scheme);

        // Try scheme-driven length first; fall back to remainder-minus-KCV.
        int remaining = s.length() - pos - 6;
        int expected;
        try {
            expected = KeyScheme.hexLenForScheme(scheme.charAt(0));
        } catch (IllegalArgumentException ex) {
            expected = remaining;
        }
        if (expected > remaining) expected = remaining;
        f.put("keyUnderLmk", s.substring(pos, pos + expected)); pos += expected;
        f.put("kcv", s.substring(pos, pos + 6));
    }

    public static byte[] buildGJ(String errCode, Map<String, Object> fields) {
        if (!"00".equals(errCode)) return ("GJ" + errCode).getBytes(StandardCharsets.US_ASCII);
        String keyType = (String) fields.getOrDefault("keyType", "001");
        String scheme  = (String) fields.getOrDefault("scheme",  "U");
        String key     = ((String) fields.get("keyUnderLmk")).toUpperCase();
        String kcv     = ((String) fields.get("kcv")).toUpperCase();
        String body = "GJ" + errCode + keyType + scheme + key + kcv;
        return body.getBytes(StandardCharsets.US_ASCII);
    }

    // =====================================================================
    // A1 — Generate Key response
    // Body: Scheme(1A) + KeyUnderLmk(hex per scheme) + [zmkScheme(1A) + KeyUnderZmk(hex)]? + KCV(6H)
    // Mode '1' from request adds the ZMK-wrapped copy block before KCV.
    // =====================================================================

    private static void parseA1Body(String s, int pos, Map<String, Object> f) {
        if (s.length() - pos < 1 + 6) { f.put("raw", s.substring(pos)); return; }
        String scheme = s.substring(pos, pos + 1); pos += 1;
        f.put("scheme", scheme);
        int hex = KeyScheme.hexLenForScheme(scheme.charAt(0));
        f.put("keyUnderLmk", s.substring(pos, pos + hex)); pos += hex;

        int remaining = s.length() - pos;
        if (remaining > 6) {
            String zmkScheme = s.substring(pos, pos + 1); pos += 1;
            f.put("zmkScheme", zmkScheme);
            int zmkHex = KeyScheme.hexLenForScheme(zmkScheme.charAt(0));
            f.put("keyUnderZmk", s.substring(pos, pos + zmkHex)); pos += zmkHex;
        }
        f.put("kcv", s.substring(pos, pos + 6));
    }

    public static byte[] buildA1(String errCode, Map<String, Object> fields) {
        if (!"00".equals(errCode)) return ("A1" + errCode).getBytes(StandardCharsets.US_ASCII);
        String scheme = (String) fields.getOrDefault("scheme", "U");
        String key    = ((String) fields.get("keyUnderLmk")).toUpperCase();
        String kcv    = ((String) fields.get("kcv")).toUpperCase();
        StringBuilder b = new StringBuilder();
        b.append("A1").append(errCode).append(scheme).append(key);
        if (fields.containsKey("keyUnderZmk")) {
            b.append((String) fields.getOrDefault("zmkScheme", "U"))
             .append(((String) fields.get("keyUnderZmk")).toUpperCase());
        }
        b.append(kcv);
        return b.toString().getBytes(StandardCharsets.US_ASCII);
    }

    // =====================================================================
    // A7 — Import Key (under ZMK) response
    // Body: LmkScheme(1A) + KeyUnderLmk(hex per scheme) + KCV(6H)
    // =====================================================================

    private static void parseA7Body(String s, int pos, Map<String, Object> f) {
        if (s.length() - pos < 1 + 6) { f.put("raw", s.substring(pos)); return; }
        String scheme = s.substring(pos, pos + 1); pos += 1;
        f.put("scheme", scheme);
        int hex = KeyScheme.hexLenForScheme(scheme.charAt(0));
        f.put("keyUnderLmk", s.substring(pos, pos + hex)); pos += hex;
        f.put("kcv", s.substring(pos, pos + 6));
    }

    public static byte[] buildA7(String errCode, Map<String, Object> fields) {
        if (!"00".equals(errCode)) return ("A7" + errCode).getBytes(StandardCharsets.US_ASCII);
        String scheme = (String) fields.getOrDefault("scheme", "U");
        String key    = ((String) fields.get("keyUnderLmk")).toUpperCase();
        String kcv    = ((String) fields.get("kcv")).toUpperCase();
        String body = "A7" + errCode + scheme + key + kcv;
        return body.getBytes(StandardCharsets.US_ASCII);
    }

    // =====================================================================
    // A9 — Export Key response
    // Body: Scheme(1A) + KeyUnderZmk(hex per scheme) + KCV(6H)
    // =====================================================================

    private static void parseA9Body(String s, int pos, Map<String, Object> f) {
        if (s.length() - pos < 1 + 6) { f.put("raw", s.substring(pos)); return; }
        String scheme = s.substring(pos, pos + 1); pos += 1;
        f.put("scheme", scheme);

        int remaining = s.length() - pos - 6;
        int expected;
        try {
            expected = KeyScheme.hexLenForScheme(scheme.charAt(0));
        } catch (IllegalArgumentException ex) {
            expected = remaining;
        }
        if (expected > remaining) expected = remaining;
        f.put("keyUnderZmk", s.substring(pos, pos + expected)); pos += expected;
        f.put("kcv", s.substring(pos, pos + 6));
    }

    public static byte[] buildA9(String errCode, Map<String, Object> fields) {
        if (!"00".equals(errCode)) return ("A9" + errCode).getBytes(StandardCharsets.US_ASCII);
        String scheme = (String) fields.getOrDefault("scheme", "U");
        String key    = ((String) fields.get("keyUnderZmk")).toUpperCase();
        String kcv    = ((String) fields.get("kcv")).toUpperCase();
        String body = "A9" + errCode + scheme + key + kcv;
        return body.getBytes(StandardCharsets.US_ASCII);
    }

    // =====================================================================
    // B5 — Form Key Block response (TR-31 / X9.143)
    // Body: BlockLen(4N) + Block(ASCII)
    // =====================================================================

    private static void parseB5Body(String s, int pos, Map<String, Object> f) {
        int len = Integer.parseInt(s.substring(pos, pos + 4)); pos += 4;
        f.put("keyBlock", s.substring(pos, Math.min(pos + len, s.length())));
        f.put("blockLength", len);
    }

    public static byte[] buildB5(String errCode, Map<String, Object> fields) {
        if (!"00".equals(errCode)) return ("B5" + errCode).getBytes(StandardCharsets.US_ASCII);
        String block = (String) fields.get("keyBlock");
        String body = "B5" + errCode + String.format("%04d", block.length()) + block;
        return body.getBytes(StandardCharsets.US_ASCII);
    }

    // =====================================================================
    // M1 — Encrypt Data Block response
    // Body: MsgLen(4N) + Ciphertext(hex)
    // =====================================================================

    private static void parseM1Body(String s, int pos, Map<String, Object> f) {
        int len = Integer.parseInt(s.substring(pos, pos + 4)); pos += 4;
        f.put("ciphertext", s.substring(pos, Math.min(pos + len * 2, s.length())));
        f.put("messageLength", len);
    }

    public static byte[] buildM1(String errCode, Map<String, Object> fields) {
        if (!"00".equals(errCode)) return ("M1" + errCode).getBytes(StandardCharsets.US_ASCII);
        String c = ((String) fields.get("ciphertext")).toUpperCase();
        int bytes = c.length() / 2;
        String body = "M1" + errCode + String.format("%04d", bytes) + c;
        return body.getBytes(StandardCharsets.US_ASCII);
    }

    // =====================================================================
    // M3 — Decrypt Data Block response
    // Body: MsgLen(4N) + Plaintext(hex)
    // =====================================================================

    private static void parseM3Body(String s, int pos, Map<String, Object> f) {
        int len = Integer.parseInt(s.substring(pos, pos + 4)); pos += 4;
        f.put("plaintext", s.substring(pos, Math.min(pos + len * 2, s.length())));
        f.put("messageLength", len);
    }

    public static byte[] buildM3(String errCode, Map<String, Object> fields) {
        if (!"00".equals(errCode)) return ("M3" + errCode).getBytes(StandardCharsets.US_ASCII);
        String plain = ((String) fields.get("plaintext")).toUpperCase();
        int bytes = plain.length() / 2;
        String body = "M3" + errCode + String.format("%04d", bytes) + plain;
        return body.getBytes(StandardCharsets.US_ASCII);
    }
}
