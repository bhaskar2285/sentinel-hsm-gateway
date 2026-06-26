package com.isc.sentinel.vendor.thales.command;

import com.isc.sentinel.vendor.thales.wire.HsmHeader;
import com.isc.sentinel.vendor.thales.wire.KeyScheme;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

/**
 * Thales RESPONSE codec: parse + build for Thales host-command responses.
 *
 * Mirrors {@link ThalesCmdBuilder} (request side). Each command pair (EI/EJ, GI/GJ, A8/A9, M2/M3)
 * has a request build/parse and a response parse/build, giving full symmetric wire codec.
 * Useful for audit replay, unit tests, wire-trace decoding and mock fixtures.
 *
 * Wire framing handled by caller — these helpers operate on the body that follows the
 * 2-byte length prefix and the echoed header.
 */
public final class ThalesCmdParser {

    private ThalesCmdParser() {}

    public record Parsed(String responseCode, String errorCode, Map<String, Object> fields) {}

    // =====================================================================
    // Top-level: dispatch on response code
    // =====================================================================

    /**
     * Parse a full Thales wire response: [echoed header][respCode(2)][errCode(2)][body...].
     */
    /**
     * Some payShield responses return a valid result alongside a non-'00' code that is a
     * warning, not a failure. DF '02' = "Warning PVK not single length" still returns the
     * IBM PIN offset (Core Host Commands p.210) — exactly what real bank DE traffic shows.
     */
    public static boolean isWarning(String responseCode, String errorCode) {
        return "02".equals(errorCode) && "DF".equals(responseCode);
    }

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
        if (!"00".equals(errCode) && !isWarning(respCode, errCode)) {
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
            case "CB" -> parseCBBody(s, pos, fields);
            case "DB" -> { /* no body — error code only */ }
            case "CX" -> parseCXBody(s, pos, fields);
            case "CZ" -> { /* no body — error code only */ }
            case "KR" -> parseKRBody(s, pos, fields);
            // Phase 2 additions
            case "JB" -> parseJBBody(s, pos, fields);
            case "DH" -> parseDHBody(s, pos, fields);
            case "DF" -> parseDFBody(s, pos, fields);
            case "DD" -> { /* no body — PIN verify result in errCode */ }
            case "EB" -> { /* no body — PIN verify result in errCode */ }
            case "ED" -> { /* no body — PIN verify result in errCode */ }
            case "CD" -> parseCDBody(s, pos, fields);
            case "BB" -> parseBBBody(s, pos, fields);
            case "EF" -> parseEFBody(s, pos, fields);
            case "M7" -> parseM7Body(s, pos, fields);
            case "M9" -> { /* no body — MAC verify result in errCode */ }
            case "GD" -> parseGDBody(s, pos, fields);
            case "JD" -> parseJDBody(s, pos, fields);
            case "JF" -> parseJDBody(s, pos, fields); // same structure as JD
            case "JH" -> parseJHBody(s, pos, fields);
            case "NP" -> parseNPBody(s, pos, fields);
            case "A3" -> parseA3Body(s, pos, fields);
            case "A5" -> parseA5Body(s, pos, fields);
            case "BV" -> parseBVBody(s, pos, fields);
            case "B3" -> parseB3Body(s, pos, fields);
            case "KX" -> parseKRBody(s, pos, fields);  // same structure as KR
            case "LR" -> parseLRBody(s, pos, fields);
            case "LT" -> {} // no body beyond error code
            case "PN" -> {} // no body beyond error code
            case "RZ" -> parseRZBody(s, pos, fields);
            // New commands
            case "HD" -> parseA1Body(s, pos, fields); // same structure as A1
            case "IB" -> parseA1Body(s, pos, fields); // same structure as A1
            case "NH" -> parseNHBody(s, pos, fields);
            case "OB" -> parseOBBody(s, pos, fields);
            case "JT" -> parseCDBody(s, pos, fields); // same structure as CD
            case "VB" -> {}                           // no body — verify result in errCode
            // Legacy / specialised
            case "PB" -> {}                           // PA ack — no body beyond error code
            case "PD" -> {}                           // PC ack — no body beyond error code
            case "GP" -> {}                           // GO PIN verify — result in error code
            case "PF" -> parsePFBody(s, pos, fields); // PE print — check data
            case "PZ" -> {}                           // PE after-print status — no body
            case "BH" -> parseJDBody(s, pos, fields); // BG — PIN under current LMK (variable LN)
            case "G1" -> parseG1Body(s, pos, fields); // G0 — translated PIN block + dst format
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
            expected = KeyScheme.keyTokenLen(s, pos - 1);
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
        int hex = KeyScheme.keyTokenLen(s, pos - 1);
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
        int hex = KeyScheme.keyTokenLen(s, pos - 1);
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
            expected = KeyScheme.keyTokenLen(s, pos - 1);
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
        // MsgLen is 4 HEX digits = number of HEX CHARS that follow (Output Format '1').
        int len = Integer.parseInt(s.substring(pos, pos + 4), 16); pos += 4;
        f.put("ciphertext", s.substring(pos, Math.min(pos + len, s.length())));
        f.put("messageLength", len / 2);
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
        // MsgLen is 4 HEX digits = number of HEX CHARS that follow (Output Format '1').
        int len = Integer.parseInt(s.substring(pos, pos + 4), 16); pos += 4;
        f.put("plaintext", s.substring(pos, Math.min(pos + len, s.length())));
        f.put("messageLength", len / 2);
    }

    public static byte[] buildM3(String errCode, Map<String, Object> fields) {
        if (!"00".equals(errCode)) return ("M3" + errCode).getBytes(StandardCharsets.US_ASCII);
        String plain = ((String) fields.get("plaintext")).toUpperCase();
        int bytes = plain.length() / 2;
        String body = "M3" + errCode + String.format("%04d", bytes) + plain;
        return body.getBytes(StandardCharsets.US_ASCII);
    }

    // =====================================================================
    // CB — Translate PIN Block response
    // Body: PINBlock(16H)
    // =====================================================================

    private static void parseCBBody(String s, int pos, Map<String, Object> f) {
        if (s.length() - pos >= 16) f.put("pinBlock", s.substring(pos, pos + 16));
        else f.put("raw", s.substring(pos));
    }

    // =====================================================================
    // CX — Generate CVV response
    // Body: CVV(3H)
    // =====================================================================

    private static void parseCXBody(String s, int pos, Map<String, Object> f) {
        if (s.length() - pos >= 3) f.put("cvv", s.substring(pos, pos + 3));
        else f.put("raw", s.substring(pos));
    }

    // =====================================================================
    // KR — Verify ARQC / Generate ARPC response
    // Body: ARPC(16H)
    // =====================================================================

    private static void parseKRBody(String s, int pos, Map<String, Object> f) {
        if (s.length() - pos >= 16) f.put("arpc", s.substring(pos, pos + 16));
        else f.put("raw", s.substring(pos));
    }

    // =====================================================================
    // JB — Generate a Random PIN response
    // Body: PIN encrypted under LMK — L digits (Variant/Key Block LMK) or 'J'+32H (AES LMK).
    // No length prefix; the encrypted PIN is the remainder of the response body.
    // =====================================================================

    private static void parseJBBody(String s, int pos, Map<String, Object> f) {
        String pin = s.substring(pos).trim();
        if (!pin.isEmpty()) f.put("pinUnderLmk", pin);
        else f.put("raw", s.substring(pos));
    }

    // =====================================================================
    // DH — Generate VISA PVV response
    // Body: PVV(4N)
    // =====================================================================

    private static void parseDHBody(String s, int pos, Map<String, Object> f) {
        if (s.length() - pos >= 4) f.put("pvv", s.substring(pos, pos + 4));
        else f.put("raw", s.substring(pos));
    }

    // =====================================================================
    // DF — Generate IBM PIN Offset response
    // Body: Offset(12N, 'F'-padded to check length)
    // =====================================================================

    private static void parseDFBody(String s, int pos, Map<String, Object> f) {
        String rest = s.substring(pos).trim();
        if (rest.isEmpty()) { f.put("raw", s.substring(pos)); return; }
        f.put("offset", rest.length() >= 12 ? rest.substring(0, 12) : rest);
    }

    // =====================================================================
    // CD — Translate PIN ZPK→ZPK response
    // Body: PINBlock(16H) + DstFmt(2N)
    // =====================================================================

    private static void parseCDBody(String s, int pos, Map<String, Object> f) {
        if (s.length() - pos >= 16) {
            f.put("pinBlock", s.substring(pos, pos + 16)); pos += 16;
            if (s.length() - pos >= 2) f.put("dstFormat", s.substring(pos, pos + 2));
        } else { f.put("raw", s.substring(pos)); }
    }

    // =====================================================================
    // BB — Encrypt a Clear PIN response
    // Body: PIN encrypted under LMK — L digits (Variant/Key Block LMK) or 'J'+32H (AES LMK).
    // No length prefix; the encrypted PIN is the remainder of the response body.
    // =====================================================================

    private static void parseBBBody(String s, int pos, Map<String, Object> f) {
        String pin = s.substring(pos).trim();
        if (!pin.isEmpty()) f.put("pinUnderLmk", pin);
        else f.put("raw", s.substring(pos));
    }

    // =====================================================================
    // EF — Derive PIN from IBM Offset response
    // Body: PINLen(2N) + PIN(variable hex digits, PINLen chars)
    // =====================================================================

    private static void parseEFBody(String s, int pos, Map<String, Object> f) {
        if (s.length() - pos < 2) { f.put("raw", s.substring(pos)); return; }
        String lenStr = s.substring(pos, pos + 2); pos += 2;
        f.put("pinLen", lenStr);
        try {
            int len = Integer.parseInt(lenStr);
            if (s.length() - pos >= len) f.put("pin", s.substring(pos, pos + len));
            else f.put("pin", s.substring(pos));
        } catch (NumberFormatException e) {
            f.put("pin", s.substring(pos));
        }
    }

    // =====================================================================
    // M7 — Generate MAC response
    // Body: MAC(16H)
    // =====================================================================

    private static void parseM7Body(String s, int pos, Map<String, Object> f) {
        if (s.length() - pos >= 16) f.put("mac", s.substring(pos, pos + 16));
        else f.put("raw", s.substring(pos));
    }

    // =====================================================================
    // GD — Export ZPK under ZMK response
    // Body: ZPKScheme(1A)+ZPKUnderZMK(hex) + KCV(6H)
    // =====================================================================

    private static void parseGDBody(String s, int pos, Map<String, Object> f) {
        if (s.length() - pos < 1 + 6) { f.put("raw", s.substring(pos)); return; }
        String scheme = s.substring(pos, pos + 1); pos += 1;
        f.put("scheme", scheme);
        int remaining = s.length() - pos - 6;
        int expected;
        try {
            expected = KeyScheme.keyTokenLen(s, pos - 1);
        } catch (IllegalArgumentException ex) {
            expected = remaining;
        }
        if (expected > remaining) expected = remaining;
        f.put("zpkUnderZmk", s.substring(pos, pos + expected)); pos += expected;
        f.put("kcv", s.substring(pos, pos + 6));
    }

    // =====================================================================
    // JD/JF — Translate PIN TPK/ZPK→LMK response
    // Body: PINLen(2N) + PINUnderLMK(16H)
    // =====================================================================

    private static void parseJDBody(String s, int pos, Map<String, Object> f) {
        // JD/JF: ErrCode already stripped. Body = PIN encrypted under LMK (LN), a
        // variable-length proprietary-format token whose length L is set by the HSM
        // "PIN Length" security setting (e.g. 13 chars on the TTB key-block LMK:
        // JF00 8699636332605). For an AES Key Block LMK it is 'J' + 32 H. There is no
        // separate length prefix, so capture the whole remaining token.
        if (s.length() - pos < 1) { f.put("raw", ""); return; }
        f.put("pinUnderLmk", s.substring(pos));
    }

    // =====================================================================
    // JH — Translate PIN LMK→ZPK response
    // Body: PINBlock(16H)
    // =====================================================================

    private static void parseJHBody(String s, int pos, Map<String, Object> f) {
        if (s.length() - pos >= 16) f.put("pinBlock", s.substring(pos, pos + 16));
        else f.put("raw", s.substring(pos));
    }

    // =====================================================================
    // NP — HSM Status response
    // Body: LmkCheckValue(16H) + Firmware(8A) + DspFw(4A) + Seq(4H) + Flags(1A)
    // =====================================================================

    private static void parseNPBody(String s, int pos, Map<String, Object> f) {
        if (s.length() - pos >= 16) { f.put("lmkCheckValue", s.substring(pos, pos + 16)); pos += 16; }
        if (s.length() - pos >= 8)  { f.put("firmware",      s.substring(pos, pos + 8));  pos += 8;  }
        if (s.length() - pos >= 4)  { f.put("dspFirmware",   s.substring(pos, pos + 4));  pos += 4;  }
        if (s.length() - pos >= 4)  { f.put("sequence",      s.substring(pos, pos + 4));  pos += 4;  }
        if (s.length() - pos >= 1)  { f.put("flags",         s.substring(pos, pos + 1));             }
    }

    // =====================================================================
    // A3 — Generate Key Component response
    // Body: Scheme(1A) + Component(hex per scheme)
    // =====================================================================

    private static void parseA3Body(String s, int pos, Map<String, Object> f) {
        if (s.length() - pos < 2) { f.put("raw", s.substring(pos)); return; }
        String scheme = s.substring(pos, pos + 1); pos += 1;
        f.put("scheme", scheme);
        int hex;
        try { hex = KeyScheme.keyTokenLen(s, pos - 1); }
        catch (IllegalArgumentException ex) { hex = s.length() - pos; }
        int end = Math.min(pos + hex, s.length());
        f.put("component", s.substring(pos, end));
        // Component Check Value (6 H) — present when the request used check flag '2'.
        if (s.length() - end >= 6) f.put("kcv", s.substring(end, end + 6));
    }

    // =====================================================================
    // A5 — Form Key from Components response
    // Body: Scheme(1A) + KeyUnderLMK(hex per scheme) + KCV(6H)
    // =====================================================================

    private static void parseA5Body(String s, int pos, Map<String, Object> f) {
        if (s.length() - pos < 1 + 6) { f.put("raw", s.substring(pos)); return; }
        String scheme = s.substring(pos, pos + 1); pos += 1;
        f.put("scheme", scheme);
        int remaining = s.length() - pos - 6;
        int expected;
        try { expected = KeyScheme.keyTokenLen(s, pos - 1); }
        catch (IllegalArgumentException ex) { expected = remaining; }
        if (expected > remaining) expected = remaining;
        f.put("keyUnderLmk", s.substring(pos, pos + expected)); pos += expected;
        f.put("kcv", s.substring(pos, pos + 6));
    }

    // =====================================================================
    // BV — Generate Key Check Value response
    // Body: CheckValue(6H)
    // =====================================================================

    private static void parseBVBody(String s, int pos, Map<String, Object> f) {
        if (s.length() - pos >= 6) f.put("kcv", s.substring(pos, pos + 6));
        else f.put("raw", s.substring(pos));
    }

    // =====================================================================
    // B3 — Echo response
    // Body: echoed data (ASCII)
    // =====================================================================

    private static void parseB3Body(String s, int pos, Map<String, Object> f) {
        f.put("echo", s.substring(pos));
    }

    // =====================================================================
    // LR — Generate HMAC response
    // Body: HMACLen(4N) + HMAC(hex, HMACLen*2 chars)
    // =====================================================================

    private static void parseLRBody(String s, int pos, Map<String, Object> f) {
        if (s.length() - pos < 4) { f.put("raw", s.substring(pos)); return; }
        int hmacBytes = Integer.parseInt(s.substring(pos, pos + 4)); pos += 4;
        int hmacHexLen = hmacBytes * 2;
        if (s.length() - pos >= hmacHexLen) f.put("hmac", s.substring(pos, pos + hmacHexLen));
        else f.put("raw", s.substring(pos));
    }

    // =====================================================================
    // RZ — Calculate/Verify CSC response
    // Mode '3' (calc): Mode(1N) + CSC5(5N) + CSC4(4N) + CSC3(3N)
    // Mode '4' (verify): Mode(1N) + R5(1N) + R4(1N) + R3(1N)
    // =====================================================================

    // =====================================================================
    // NH — Decrypt an Encrypted PIN response
    // Body: clear PIN (L H, left-justified 'F'-padded) + ReferenceNumber(12 N).
    // No length prefix; reference number is the trailing 12 digits.
    // =====================================================================

    private static void parseNHBody(String s, int pos, Map<String, Object> f) {
        String rest = s.substring(pos).trim();
        if (rest.length() >= 12) {
            String ref = rest.substring(rest.length() - 12);
            String pin = rest.substring(0, rest.length() - 12).replaceAll("[Ff]+$", "");
            f.put("clearPin", pin);
            f.put("referenceNumber", ref);
        } else {
            f.put("raw", rest);
        }
    }

    // =====================================================================
    // OB — Generate Random Data response
    // Body: Data(hex, numBytes*2 chars)
    // =====================================================================

    private static void parseOBBody(String s, int pos, Map<String, Object> f) {
        f.put("dataHex", s.substring(pos));
    }

    private static void parseRZBody(String s, int pos, Map<String, Object> f) {
        if (s.length() - pos < 1) { f.put("raw", s.substring(pos)); return; }
        String mode = s.substring(pos, pos + 1); pos += 1;
        f.put("mode", mode);
        if ("3".equals(mode)) {
            if (s.length() - pos < 12) { f.put("raw", s.substring(pos)); return; }
            f.put("csc5", s.substring(pos, pos + 5)); pos += 5;
            f.put("csc4", s.substring(pos, pos + 4)); pos += 4;
            f.put("csc3", s.substring(pos, pos + 3));
        } else if ("4".equals(mode)) {
            if (s.length() - pos < 3) { f.put("raw", s.substring(pos)); return; }
            f.put("result5", s.substring(pos, pos + 1)); pos += 1;
            f.put("result4", s.substring(pos, pos + 1)); pos += 1;
            f.put("result3", s.substring(pos, pos + 1));
        } else {
            f.put("raw", s.substring(pos));
        }
    }

    // PF — PE (Print PIN) "before printing" response: PIN check value + reference
    // number check value (L + 12 N). Length L depends on the configured PIN length,
    // so capture the whole remaining token as a single check-data field.
    private static void parsePFBody(String s, int pos, Map<String, Object> f) {
        if (s.length() - pos < 1) { f.put("raw", ""); return; }
        f.put("checkData", s.substring(pos));
    }

    // G1 — G0 (DUKPT PIN translate) response: DestPINBlock(16H) + DestFmt(2N).
    private static void parseG1Body(String s, int pos, Map<String, Object> f) {
        if (s.length() - pos < 16) { f.put("raw", s.substring(pos)); return; }
        f.put("pinBlock", s.substring(pos, pos + 16)); pos += 16;
        if (s.length() - pos >= 2) f.put("pinBlockFormat", s.substring(pos, pos + 2));
    }
}
