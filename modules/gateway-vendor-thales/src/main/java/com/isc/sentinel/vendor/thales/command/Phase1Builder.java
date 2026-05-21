package com.isc.sentinel.vendor.thales.command;

import com.isc.sentinel.vendor.thales.wire.HsmHeader;
import com.isc.sentinel.vendor.thales.wire.HsmWireMessage;
import com.isc.sentinel.vendor.thales.wire.KeyScheme;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

/**
 * Phase-1 REQUEST codec: build + parse for EI, GI, A8, M2.
 *
 * Refs: payShield 10K Host Programmer's Manual, Core Host Commands V1.0
 *   EI p.167  RSA Key Pair Generate
 *   GI p.182  Import Key/Data under RSA
 *   A8 p.59   Export Key (under ZMK/KBPK)
 *   M2 p.384  Decrypt Data Block
 *
 * Each command has paired build*() (params -> wire) and parse*() (wire -> params).
 * Round-trip safe: parse(build(p)) == p (modulo case normalisation on hex).
 */
public final class Phase1Builder {

    private Phase1Builder() {}

    // =====================================================================
    // EI — Generate RSA Key Pair
    // Body: KeyType(1A) + ModulusBits(4N) + Encoding(1A) + PubExpLen(4N) + PubExp(hex)
    // =====================================================================

    public static HsmWireMessage buildEI(HsmHeader header, Map<String, Object> params) {
        String keyType  = (String) params.getOrDefault("keyType", "2");
        int    modBits  = ((Number) params.getOrDefault("modulusBits", 2048)).intValue();
        String encoding = (String) params.getOrDefault("encoding", "0");
        String expHex   = ((String) params.getOrDefault("publicExponentHex", "010001")).toUpperCase();

        String expLen = String.format("%04d", expHex.length() / 2);
        String modLen = String.format("%04d", modBits);

        String body = keyType + modLen + encoding + expLen + expHex;
        return new HsmWireMessage(header, "EI", body.getBytes(StandardCharsets.US_ASCII), null);
    }

    public static Map<String, Object> parseEI(byte[] body) {
        String s = new String(body, StandardCharsets.US_ASCII);
        if (!s.startsWith("EI") || s.length() < 12) {
            throw new IllegalArgumentException("EI body malformed");
        }
        int pos = 2;
        Map<String, Object> p = new HashMap<>();
        p.put("keyType",     s.substring(pos, pos + 1)); pos += 1;
        p.put("modulusBits", Integer.parseInt(s.substring(pos, pos + 4))); pos += 4;
        p.put("encoding",    s.substring(pos, pos + 1)); pos += 1;
        int expLen = Integer.parseInt(s.substring(pos, pos + 4)); pos += 4;
        p.put("publicExponentHex", s.substring(pos, pos + expLen * 2));
        return p;
    }

    // =====================================================================
    // GI — Import Key/Data under RSA Public Key
    // Body: Mode(1A) + HashId(2N) + WPKLen(4N) + WPK(hex) + WKLen(4N) + WK(hex)
    // =====================================================================

    public static HsmWireMessage buildGI(HsmHeader header, Map<String, Object> params) {
        String mode   = (String) params.getOrDefault("mode", "0");
        String hashId = (String) params.getOrDefault("hashId", "01");
        String wpk    = ((String) params.get("wrappingPublicKey")).toUpperCase();
        String wk     = ((String) params.get("wrappedKey")).toUpperCase();

        String body = mode + hashId
                    + String.format("%04d", wpk.length() / 2) + wpk
                    + String.format("%04d", wk.length()  / 2) + wk;
        return new HsmWireMessage(header, "GI", body.getBytes(StandardCharsets.US_ASCII), null);
    }

    public static Map<String, Object> parseGI(byte[] body) {
        String s = new String(body, StandardCharsets.US_ASCII);
        if (!s.startsWith("GI") || s.length() < 15) {
            throw new IllegalArgumentException("GI body malformed");
        }
        int pos = 2;
        Map<String, Object> p = new HashMap<>();
        p.put("mode",   s.substring(pos, pos + 1)); pos += 1;
        p.put("hashId", s.substring(pos, pos + 2)); pos += 2;

        int wpkLen = Integer.parseInt(s.substring(pos, pos + 4)); pos += 4;
        p.put("wrappingPublicKey", s.substring(pos, pos + wpkLen * 2)); pos += wpkLen * 2;

        int wkLen  = Integer.parseInt(s.substring(pos, pos + 4)); pos += 4;
        p.put("wrappedKey", s.substring(pos, pos + wkLen * 2));
        return p;
    }

    // =====================================================================
    // A8 — Export Key (wrap under ZMK/KBPK)
    // Body: ZmkType(3H) + KeyType(3H) + ZmkScheme(1A) + ZmkUnderLmk(hex)
    //     + KeyScheme(1A) + KeyUnderLmk(hex) + OutScheme(1A)
    // =====================================================================

    public static HsmWireMessage buildA8(HsmHeader header, Map<String, Object> params) {
        String zmkType    = (String) params.getOrDefault("zmkKeyType", "000");
        String keyType    = (String) params.getOrDefault("keyKeyType", "001");
        String zmkScheme  = (String) params.getOrDefault("zmkScheme", "U");
        String zmkUnder   = ((String) params.get("zmkUnderLmk")).toUpperCase();
        String keyScheme  = (String) params.getOrDefault("keyScheme", "U");
        String keyUnder   = ((String) params.get("keyUnderLmk")).toUpperCase();
        String outScheme  = (String) params.getOrDefault("outScheme", "U");

        String body = zmkType + keyType
                    + zmkScheme + zmkUnder
                    + keyScheme + keyUnder
                    + outScheme;
        return new HsmWireMessage(header, "A8", body.getBytes(StandardCharsets.US_ASCII), null);
    }

    public static Map<String, Object> parseA8(byte[] body) {
        String s = new String(body, StandardCharsets.US_ASCII);
        if (!s.startsWith("A8") || s.length() < 9) {
            throw new IllegalArgumentException("A8 body malformed");
        }
        int pos = 2;
        Map<String, Object> p = new HashMap<>();
        p.put("zmkKeyType", s.substring(pos, pos + 3)); pos += 3;
        p.put("keyKeyType", s.substring(pos, pos + 3)); pos += 3;

        String zmkScheme = s.substring(pos, pos + 1); pos += 1;
        int zmkHex = KeyScheme.hexLenForScheme(zmkScheme.charAt(0));
        p.put("zmkScheme", zmkScheme);
        p.put("zmkUnderLmk", s.substring(pos, pos + zmkHex)); pos += zmkHex;

        String keyScheme = s.substring(pos, pos + 1); pos += 1;
        int keyHex = KeyScheme.hexLenForScheme(keyScheme.charAt(0));
        p.put("keyScheme", keyScheme);
        p.put("keyUnderLmk", s.substring(pos, pos + keyHex)); pos += keyHex;

        p.put("outScheme", s.substring(pos, pos + 1));
        return p;
    }

    // =====================================================================
    // M2 — Decrypt Data Block
    // Body: Mode(2A) + InFmt(1A) + OutFmt(1A) + KeyType(3A) + KeyScheme(1A)
    //     + KeyUnderLmk(hex per scheme) + MsgLen(4N) + [IV(32H) if CBC] + Msg(hex)
    //
    // NOTE: legacy callers pass "keyHex" = "<scheme><hex>" concatenated; we accept either
    // (a) explicit keyScheme + keyUnderLmk fields, or
    // (b) legacy keyHex starting with scheme byte.
    // =====================================================================

    public static HsmWireMessage buildM2(HsmHeader header, Map<String, Object> params) {
        String mode    = (String) params.getOrDefault("mode", "01");
        String inFmt   = (String) params.getOrDefault("inputFormat",  "0");
        String outFmt  = (String) params.getOrDefault("outputFormat", "0");
        String keyType = (String) params.getOrDefault("keyType", "00A");

        String keyScheme;
        String keyUnder;
        if (params.containsKey("keyScheme") && params.containsKey("keyUnderLmk")) {
            keyScheme = ((String) params.get("keyScheme")).toUpperCase();
            keyUnder  = ((String) params.get("keyUnderLmk")).toUpperCase();
        } else {
            String legacy = ((String) params.get("keyHex")).toUpperCase();
            keyScheme = legacy.substring(0, 1);
            keyUnder  = legacy.substring(1);
        }

        String iv  = ((String) params.getOrDefault("iv", "")).toUpperCase();
        String msg = ((String) params.get("messageHex")).toUpperCase();
        int msgBytes = msg.length() / 2;

        StringBuilder b = new StringBuilder();
        b.append(mode).append(inFmt).append(outFmt).append(keyType)
         .append(keyScheme).append(keyUnder)
         .append(String.format("%04d", msgBytes));
        if ("01".equals(mode) && !iv.isEmpty()) b.append(iv);
        b.append(msg);

        return new HsmWireMessage(header, "M2", b.toString().getBytes(StandardCharsets.US_ASCII), null);
    }

    // =====================================================================
    // A0 — Generate a (Symmetric) Key under LMK
    // Body: Mode(1A) + KeyType(3N) + KeyScheme(1A)
    //       [+ ZmkScheme(1A) + ZmkUnderLmk(hex) + OutScheme(1A) if mode=1]
    // Mode '0' = key under LMK only; '1' = key + ZMK-wrapped copy.
    // =====================================================================

    public static HsmWireMessage buildA0(HsmHeader header, Map<String, Object> params) {
        String mode      = (String) params.getOrDefault("mode", "0");
        String keyType   = (String) params.getOrDefault("keyType", "001");
        String keyScheme = (String) params.getOrDefault("keyScheme", "U");

        StringBuilder b = new StringBuilder();
        b.append(mode).append(keyType).append(keyScheme);

        if ("1".equals(mode)) {
            String zmkScheme = (String) params.getOrDefault("zmkScheme", "U");
            String zmkUnder  = ((String) params.get("zmkUnderLmk")).toUpperCase();
            String outScheme = (String) params.getOrDefault("outScheme", "U");
            b.append(zmkScheme).append(zmkUnder).append(outScheme);
        }
        return new HsmWireMessage(header, "A0", b.toString().getBytes(StandardCharsets.US_ASCII), null);
    }

    public static Map<String, Object> parseA0(byte[] body) {
        String s = new String(body, StandardCharsets.US_ASCII);
        if (!s.startsWith("A0") || s.length() < 7) {
            throw new IllegalArgumentException("A0 body malformed");
        }
        int pos = 2;
        Map<String, Object> p = new HashMap<>();
        String mode = s.substring(pos, pos + 1); pos += 1;
        p.put("mode", mode);
        p.put("keyType",   s.substring(pos, pos + 3)); pos += 3;
        p.put("keyScheme", s.substring(pos, pos + 1)); pos += 1;

        if ("1".equals(mode) && pos < s.length()) {
            String zmkScheme = s.substring(pos, pos + 1); pos += 1;
            int zmkHex = KeyScheme.hexLenForScheme(zmkScheme.charAt(0));
            p.put("zmkScheme", zmkScheme);
            p.put("zmkUnderLmk", s.substring(pos, pos + zmkHex)); pos += zmkHex;
            p.put("outScheme", s.substring(pos, pos + 1));
        }
        return p;
    }

    // =====================================================================
    // B4 — Form Key Block (TR-31 / X9.143 wrap by HSM)
    // Body: KbpkType(3H) + KeyType(3H) + KbpkScheme(1A) + KbpkUnderLmk(hex)
    //     + KeyScheme(1A) + KeyUnderLmk(hex) + Format(1A) + Usage(2A)
    //     + Algo(1A) + Mode(1A) + Export(1A)
    //
    // Format: 'D'=TR-31 Format D (AES), 'B'=TR-31 Format B (3DES), 'X'=X9.143
    // Clear keys never leave HSM — wrap happens HSM-side with KBPK-derived KBEK/KBAK.
    // =====================================================================

    public static HsmWireMessage buildB4(HsmHeader header, Map<String, Object> params) {
        String kbpkType   = (String) params.getOrDefault("kbpkKeyType", "002");   // KBPK key type
        String keyType    = (String) params.getOrDefault("keyKeyType", "001");
        String kbpkScheme = (String) params.getOrDefault("kbpkScheme", "U");
        String kbpkUnder  = ((String) params.get("kbpkUnderLmk")).toUpperCase();
        String keyScheme  = (String) params.getOrDefault("keyScheme", "U");
        String keyUnder   = ((String) params.get("keyUnderLmk")).toUpperCase();
        String format     = (String) params.getOrDefault("blockFormat", "D");
        String usage      = (String) params.getOrDefault("usage", "K0");
        String algo       = (String) params.getOrDefault("algo", "T");
        String mode       = (String) params.getOrDefault("mode", "E");
        String export     = (String) params.getOrDefault("export", "E");

        String body = kbpkType + keyType
                    + kbpkScheme + kbpkUnder
                    + keyScheme + keyUnder
                    + format + usage + algo + mode + export;
        return new HsmWireMessage(header, "B4", body.getBytes(StandardCharsets.US_ASCII), null);
    }

    public static Map<String, Object> parseB4(byte[] body) {
        String s = new String(body, StandardCharsets.US_ASCII);
        if (!s.startsWith("B4") || s.length() < 14) {
            throw new IllegalArgumentException("B4 body malformed");
        }
        int pos = 2;
        Map<String, Object> p = new HashMap<>();
        p.put("kbpkKeyType", s.substring(pos, pos + 3)); pos += 3;
        p.put("keyKeyType",  s.substring(pos, pos + 3)); pos += 3;

        String kbpkScheme = s.substring(pos, pos + 1); pos += 1;
        int kbpkHex = KeyScheme.hexLenForScheme(kbpkScheme.charAt(0));
        p.put("kbpkScheme",   kbpkScheme);
        p.put("kbpkUnderLmk", s.substring(pos, pos + kbpkHex)); pos += kbpkHex;

        String keyScheme = s.substring(pos, pos + 1); pos += 1;
        int keyHex = KeyScheme.hexLenForScheme(keyScheme.charAt(0));
        p.put("keyScheme",   keyScheme);
        p.put("keyUnderLmk", s.substring(pos, pos + keyHex)); pos += keyHex;

        p.put("blockFormat", s.substring(pos, pos + 1)); pos += 1;
        p.put("usage",       s.substring(pos, pos + 2)); pos += 2;
        p.put("algo",        s.substring(pos, pos + 1)); pos += 1;
        p.put("mode",        s.substring(pos, pos + 1)); pos += 1;
        p.put("export",      s.substring(pos, pos + 1));
        return p;
    }

    public static Map<String, Object> parseM2(byte[] body) {
        String s = new String(body, StandardCharsets.US_ASCII);
        if (!s.startsWith("M2") || s.length() < 12) {
            throw new IllegalArgumentException("M2 body malformed");
        }
        int pos = 2;
        Map<String, Object> p = new HashMap<>();
        String mode  = s.substring(pos, pos + 2); pos += 2;
        p.put("mode", mode);
        p.put("inputFormat",  s.substring(pos, pos + 1)); pos += 1;
        p.put("outputFormat", s.substring(pos, pos + 1)); pos += 1;
        p.put("keyType",      s.substring(pos, pos + 3)); pos += 3;

        String keyScheme = s.substring(pos, pos + 1); pos += 1;
        int keyHex = KeyScheme.hexLenForScheme(keyScheme.charAt(0));
        p.put("keyScheme",    keyScheme);
        p.put("keyUnderLmk",  s.substring(pos, pos + keyHex)); pos += keyHex;

        int msgLen = Integer.parseInt(s.substring(pos, pos + 4)); pos += 4;
        if ("01".equals(mode)) {
            p.put("iv", s.substring(pos, pos + 32)); pos += 32;
        }
        p.put("messageHex", s.substring(pos, pos + msgLen * 2));
        return p;
    }
}
