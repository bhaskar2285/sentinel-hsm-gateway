package com.isc.sentinel.vendor.thales.command;

import com.isc.sentinel.vendor.thales.wire.HsmHeader;
import com.isc.sentinel.vendor.thales.wire.HsmWireMessage;
import com.isc.sentinel.vendor.thales.wire.KeyScheme;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

/**
 * Thales REQUEST codec: build + parse for Thales host commands.
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
public final class ThalesCmdBuilder {

    private ThalesCmdBuilder() {}

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
    // A6 — Import Key (under ZMK) — symmetric-key import counterpart to GI
    // Body: KeyType(3N) + ZmkScheme(1A) + ZmkUnderLmk(hex)
    //     + KeyScheme(1A) + KeyUnderZmk(hex) + LmkScheme(1A)
    // =====================================================================

    public static HsmWireMessage buildA6(HsmHeader header, Map<String, Object> params) {
        String keyType    = (String) params.getOrDefault("keyType", "001");
        String zmkScheme  = (String) params.getOrDefault("zmkScheme", "U");
        String zmkUnder   = ((String) params.get("zmkUnderLmk")).toUpperCase();
        String keyScheme  = (String) params.getOrDefault("keyScheme", "U");
        String keyUnderZ  = ((String) params.get("keyUnderZmk")).toUpperCase();
        String lmkScheme  = (String) params.getOrDefault("lmkScheme", "U");

        String body = keyType
                    + zmkScheme + zmkUnder
                    + keyScheme + keyUnderZ
                    + lmkScheme;
        return new HsmWireMessage(header, "A6", body.getBytes(StandardCharsets.US_ASCII), null);
    }

    public static Map<String, Object> parseA6(byte[] body) {
        String s = new String(body, StandardCharsets.US_ASCII);
        if (!s.startsWith("A6") || s.length() < 8) {
            throw new IllegalArgumentException("A6 body malformed");
        }
        int pos = 2;
        Map<String, Object> p = new HashMap<>();
        p.put("keyType", s.substring(pos, pos + 3)); pos += 3;

        String zmkScheme = s.substring(pos, pos + 1); pos += 1;
        int zmkHex = KeyScheme.keyTokenLen(s, pos - 1);
        p.put("zmkScheme",   zmkScheme);
        p.put("zmkUnderLmk", s.substring(pos, pos + zmkHex)); pos += zmkHex;

        String keyScheme = s.substring(pos, pos + 1); pos += 1;
        int keyHex = KeyScheme.keyTokenLen(s, pos - 1);
        p.put("keyScheme",   keyScheme);
        p.put("keyUnderZmk", s.substring(pos, pos + keyHex)); pos += keyHex;

        p.put("lmkScheme",   s.substring(pos, pos + 1));
        return p;
    }

    // =====================================================================
    // M0 — Encrypt Data Block (mirror of M2)
    // Body: Mode(2A) + InFmt(1A) + OutFmt(1A) + KeyType(3A) + KeyScheme(1A)
    //     + KeyUnderLmk(hex per scheme) + MsgLen(4N) + [IV(32H) if CBC] + Plain(hex)
    // =====================================================================

    public static HsmWireMessage buildM0(HsmHeader header, Map<String, Object> params) {
        // payShield Core Host Commands p.382. Message Length is 4 HEX digits = BYTE count
        // (NOT decimal); with Input Format '0' the Message is sent as RAW BINARY. Output
        // Format '1' makes the M1 response hex (string-parseable). Confirmed live (err 00)
        // and against the TTB trace (mode '00', inFmt '0', outFmt '1', msgLen X'0040 = 64 bytes).
        String mode    = (String) params.getOrDefault("mode", "00");        // 00=ECB, 01=CBC
        String inFmt   = (String) params.getOrDefault("inputFormat",  "0"); // 0=binary
        String outFmt  = (String) params.getOrDefault("outputFormat", "1"); // 1=hex response
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

        String iv    = ((String) params.getOrDefault("iv", "")).toUpperCase();
        String plain = ((String) params.get("plaintextHex")).toUpperCase();
        byte[] dataBytes = java.util.HexFormat.of().parseHex(plain);
        String msgLen = String.format("%04X", dataBytes.length);

        StringBuilder head = new StringBuilder();
        head.append(mode).append(inFmt).append(outFmt).append(keyType)
            .append(keyScheme).append(keyUnder).append(msgLen);
        if ("01".equals(mode) && !iv.isEmpty()) head.append(iv);

        byte[] prefix = head.toString().getBytes(StandardCharsets.US_ASCII);
        byte[] body   = new byte[prefix.length + dataBytes.length];
        System.arraycopy(prefix,    0, body, 0,             prefix.length);
        System.arraycopy(dataBytes, 0, body, prefix.length, dataBytes.length);
        return new HsmWireMessage(header, "M0", body, null);
    }

    public static Map<String, Object> parseM0(byte[] body) {
        String s = new String(body, StandardCharsets.US_ASCII);
        if (!s.startsWith("M0") || s.length() < 12) {
            throw new IllegalArgumentException("M0 body malformed");
        }
        int pos = 2;
        Map<String, Object> p = new HashMap<>();
        String mode  = s.substring(pos, pos + 2); pos += 2;
        p.put("mode", mode);
        p.put("inputFormat",  s.substring(pos, pos + 1)); pos += 1;
        p.put("outputFormat", s.substring(pos, pos + 1)); pos += 1;
        p.put("keyType",      s.substring(pos, pos + 3)); pos += 3;

        String keyScheme = s.substring(pos, pos + 1); pos += 1;
        int keyHex = KeyScheme.keyTokenLen(s, pos - 1);
        p.put("keyScheme",   keyScheme);
        p.put("keyUnderLmk", s.substring(pos, pos + keyHex)); pos += keyHex;

        int msgLen = Integer.parseInt(s.substring(pos, pos + 4)); pos += 4;
        if ("01".equals(mode)) {
            p.put("iv", s.substring(pos, pos + 32)); pos += 32;
        }
        p.put("plaintextHex", s.substring(pos, pos + msgLen * 2));
        return p;
    }

    // =====================================================================
    // A8 — Export Key (wrap under ZMK/KBPK)
    // Body: ZmkType(3H) + KeyType(3H) + ZmkScheme(1A) + ZmkUnderLmk(hex)
    //     + KeyScheme(1A) + KeyUnderLmk(hex) + OutScheme(1A)
    // =====================================================================

    public static HsmWireMessage buildA8(HsmHeader header, Map<String, Object> params) {
        String keyType    = (String) params.getOrDefault("keyKeyType", "001");
        String zmkScheme  = (String) params.getOrDefault("zmkScheme", "U");
        String zmkUnder   = ((String) params.get("zmkUnderLmk")).toUpperCase();
        String keyScheme  = (String) params.getOrDefault("keyScheme", "U");
        String keyUnder   = ((String) params.get("keyUnderLmk")).toUpperCase();
        String outScheme  = (String) params.getOrDefault("outScheme", "U");

        // Standard Thales A8: one KeyType (LMK pair of key being exported); ZMK always pair 000.
        String body = keyType
                    + zmkScheme + zmkUnder
                    + keyScheme + keyUnder
                    + outScheme;
        return new HsmWireMessage(header, "A8", body.getBytes(StandardCharsets.US_ASCII), null);
    }

    public static Map<String, Object> parseA8(byte[] body) {
        String s = new String(body, StandardCharsets.US_ASCII);
        if (!s.startsWith("A8") || s.length() < 6) {
            throw new IllegalArgumentException("A8 body malformed");
        }
        int pos = 2;
        Map<String, Object> p = new HashMap<>();
        p.put("keyKeyType", s.substring(pos, pos + 3)); pos += 3;

        String zmkScheme = s.substring(pos, pos + 1); pos += 1;
        int zmkHex = KeyScheme.keyTokenLen(s, pos - 1);
        p.put("zmkScheme", zmkScheme);
        p.put("zmkUnderLmk", s.substring(pos, pos + zmkHex)); pos += zmkHex;

        String keyScheme = s.substring(pos, pos + 1); pos += 1;
        int keyHex = KeyScheme.keyTokenLen(s, pos - 1);
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
        // Mirror of M0 (p.385). MsgLen = 4 HEX digits = BYTE count; with Input Format '0'
        // the ciphertext Message is RAW BINARY; Output Format '1' => hex M3 response.
        String mode    = (String) params.getOrDefault("mode", "00");
        String inFmt   = (String) params.getOrDefault("inputFormat",  "0");
        String outFmt  = (String) params.getOrDefault("outputFormat", "1");
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
        byte[] dataBytes = java.util.HexFormat.of().parseHex(msg);
        String msgLen = String.format("%04X", dataBytes.length);

        StringBuilder head = new StringBuilder();
        head.append(mode).append(inFmt).append(outFmt).append(keyType)
            .append(keyScheme).append(keyUnder).append(msgLen);
        if ("01".equals(mode) && !iv.isEmpty()) head.append(iv);

        byte[] prefix = head.toString().getBytes(StandardCharsets.US_ASCII);
        byte[] body   = new byte[prefix.length + dataBytes.length];
        System.arraycopy(prefix,    0, body, 0,             prefix.length);
        System.arraycopy(dataBytes, 0, body, prefix.length, dataBytes.length);
        return new HsmWireMessage(header, "M2", body, null);
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
            int zmkHex = KeyScheme.keyTokenLen(s, pos - 1);
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
        int kbpkHex = KeyScheme.keyTokenLen(s, pos - 1);
        p.put("kbpkScheme",   kbpkScheme);
        p.put("kbpkUnderLmk", s.substring(pos, pos + kbpkHex)); pos += kbpkHex;

        String keyScheme = s.substring(pos, pos + 1); pos += 1;
        int keyHex = KeyScheme.keyTokenLen(s, pos - 1);
        p.put("keyScheme",   keyScheme);
        p.put("keyUnderLmk", s.substring(pos, pos + keyHex)); pos += keyHex;

        p.put("blockFormat", s.substring(pos, pos + 1)); pos += 1;
        p.put("usage",       s.substring(pos, pos + 2)); pos += 2;
        p.put("algo",        s.substring(pos, pos + 1)); pos += 1;
        p.put("mode",        s.substring(pos, pos + 1)); pos += 1;
        p.put("export",      s.substring(pos, pos + 1));
        return p;
    }

    // =====================================================================
    // CA — Translate PIN Block (TPK → ZPK/BDK), p.278
    // Simulator wire: TPKScheme(1A)+TPK(hex) + ZPKScheme(1A)+ZPK(hex) + MaxPINLen(2N)
    //     + PINBlock(16H) + SrcFmt(2N) + DstFmt(2N) + PAN(12N)
    // Response CB: ErrCode(2) + PINBlock(16H)
    // NOTE: simulator decrypts both keys under LMK pair "001" (ZPK pair).
    // =====================================================================

    public static HsmWireMessage buildCA(HsmHeader header, Map<String, Object> params) {
        String tpkScheme = (String) params.getOrDefault("tpkScheme", "U");
        String tpkHex    = ((String) params.get("tpkHex")).toUpperCase();
        String zpkScheme = (String) params.getOrDefault("zpkScheme", "U");
        String zpkHex    = ((String) params.get("zpkHex")).toUpperCase();
        String maxLen    = (String) params.getOrDefault("maxPinLen", "12");
        String pinBlock  = ((String) params.get("pinBlock")).toUpperCase();
        String fmt       = (String) params.getOrDefault("pinBlockFormat", "01");
        String dstFmt    = (String) params.getOrDefault("dstPinBlockFormat", fmt);
        String pan       = (String) params.get("pan");

        // srcFmt + dstFmt both required; send same value if not separately specified
        String body = tpkScheme + tpkHex + zpkScheme + zpkHex + maxLen + pinBlock + fmt + dstFmt + pan;
        return new HsmWireMessage(header, "CA", body.getBytes(StandardCharsets.US_ASCII), null);
    }

    // =====================================================================
    // DA — Verify Terminal PIN (IBM 3624 offset), p.256
    // Simulator wire: TPKType(3H) + PVKType(3H) + MaxPIN(2N)
    //     + PVKScheme(1A)+PVK(hex) + TPKScheme(1A)+TPK(hex)
    //     + PINBlock(16H) + PINBlockFmt(2N) + PAN(12N)
    //     + Dectab(16H) + PINValidation(12N) + Offset(8N)
    // Response DB: ErrCode(2)
    // =====================================================================

    public static HsmWireMessage buildDA(HsmHeader header, Map<String, Object> params) {
        // payShield Core Host Commands p.256. Field order (Variant & 3DES Key Block LMK):
        //   TPK + PVK + MaxPINLen(2) + PINBlock(16) + Fmt(2) + CheckLen(2) + PAN(12)
        //   + DecimTable(16) + PINValidationData(12) + Offset(12)
        // NOTE: NO 3-digit key-type prefixes (the type is carried in the key block header /
        // is implicit for the variant pair), and TPK comes before PVK. Confirmed against the
        // live TTB capture (RSM5 DA …).
        String tpkScheme   = (String) params.getOrDefault("tpkScheme", "U");
        String tpkHex      = ((String) params.get("tpkHex")).toUpperCase();
        String pvkScheme   = (String) params.getOrDefault("pvkScheme", "U");
        String pvkHex      = ((String) params.get("pvkHex")).toUpperCase();
        String maxPin      = (String) params.getOrDefault("maxPinLen", "12");
        String pinBlock    = ((String) params.get("pinBlock")).toUpperCase();
        String fmt         = (String) params.getOrDefault("pinBlockFormat", "01");
        String checkLen    = String.format("%02d", Integer.parseInt((String) params.getOrDefault("checkLen", "4")));
        String pan         = (String) params.get("pan");
        // pan12: rightmost 12 digits excluding check digit
        String pan12       = pan.length() > 12 ? pan.substring(pan.length() - 13, pan.length() - 1) : pan;
        String dectab      = (String) params.getOrDefault("dectab", "0123456789012345");
        String validation  = (String) params.getOrDefault("pinValidationData", pan12);
        String offset      = (String) params.getOrDefault("pinOffset", "000000000000");

        String body = tpkScheme + tpkHex + pvkScheme + pvkHex
                    + maxPin + pinBlock + fmt + checkLen + pan12
                    + dectab.toUpperCase() + validation.toUpperCase() + offset.toUpperCase();
        return new HsmWireMessage(header, "DA", body.getBytes(StandardCharsets.US_ASCII), null);
    }

    // =====================================================================
    // CW — Generate CVV/CVC/CVV2, Core Host Commands
    // Wire: CVK(scheme+hex) + PAN + ';' + Expiry(4N YYMM) + ServiceCode(3N)
    // PAN is the full account number terminated by ';'. No key-type prefix.
    // Response CX: ErrCode(2) + CVV(3N)
    // =====================================================================

    public static HsmWireMessage buildCW(HsmHeader header, Map<String, Object> params) {
        String cvkaScheme = (String) params.getOrDefault("cvkaScheme", "U");
        String cvkaHex    = ((String) params.get("cvkaHex")).toUpperCase();
        String pan        = (String) params.get("pan");
        String expDate    = (String) params.get("expDate");   // YYMM
        String svcCode    = (String) params.getOrDefault("serviceCode", "101");

        String body = cvkaScheme + cvkaHex + pan + ";" + expDate + svcCode;
        return new HsmWireMessage(header, "CW", body.getBytes(StandardCharsets.US_ASCII), null);
    }

    // =====================================================================
    // CY — Verify CVV/CVC/CVV2, Core Host Commands
    // Wire: CVK(scheme+hex) + CVV(3N) + PAN + ';' + Expiry(4N) + ServiceCode(3N)
    // CVV comes immediately after the key. Response CZ: ErrCode(2) only.
    // =====================================================================

    public static HsmWireMessage buildCY(HsmHeader header, Map<String, Object> params) {
        String cvkaScheme = (String) params.getOrDefault("cvkaScheme", "U");
        String cvkaHex    = ((String) params.get("cvkaHex")).toUpperCase();
        String pan        = (String) params.get("pan");
        String expDate    = (String) params.get("expDate");
        String svcCode    = (String) params.getOrDefault("serviceCode", "101");
        String cvv        = (String) params.get("cvv");

        String body = cvkaScheme + cvkaHex + cvv + pan + ";" + expDate + svcCode;
        return new HsmWireMessage(header, "CY", body.getBytes(StandardCharsets.US_ASCII), null);
    }

    // =====================================================================
    // KQ — Verify ARQC / Generate ARPC (EMV chip), p.454
    // Simulator wire: IMKType(3H) + IMKScheme(1A)+IMK(hex) + PAN(12N) + PSN(2N)
    //     + ARQC(16H) + TxnDataLen(4H = byte count as hex) + TxnData(raw binary) + ARC(4H)
    // TxnData is raw binary bytes (not hex-encoded); callers pass hex string which we decode.
    // Response KR: ErrCode(2) + ARPC(16H)
    // =====================================================================

    public static HsmWireMessage buildKQ(HsmHeader header, Map<String, Object> params) {
        String imkKeyType = (String) params.getOrDefault("imkKeyType", "00A");
        String imkScheme  = (String) params.getOrDefault("imkScheme", "U");
        String imkHex     = ((String) params.get("imkHex")).toUpperCase();
        String pan        = (String) params.get("pan");
        String panSeqNo   = (String) params.getOrDefault("panSeqNo", "00");
        String arqc       = ((String) params.get("arqc")).toUpperCase();
        String transDataHex = ((String) params.get("transData")).toUpperCase();
        String arc        = ((String) params.get("arc")).toUpperCase();

        // pan12: rightmost 12 digits excluding check digit
        String pan12 = pan.length() > 12 ? pan.substring(pan.length() - 13, pan.length() - 1) : pan;
        // TxnData on wire is raw binary; decode caller's hex string
        byte[] txnDataBytes = java.util.HexFormat.of().parseHex(transDataHex);
        String txnDataLen   = String.format("%04X", txnDataBytes.length);

        byte[] prefix = (imkKeyType + imkScheme + imkHex + pan12 + panSeqNo + arqc + txnDataLen)
                        .getBytes(StandardCharsets.US_ASCII);
        byte[] suffix = arc.getBytes(StandardCharsets.US_ASCII);
        byte[] body   = new byte[prefix.length + txnDataBytes.length + suffix.length];
        System.arraycopy(prefix,       0, body, 0,                                     prefix.length);
        System.arraycopy(txnDataBytes, 0, body, prefix.length,                         txnDataBytes.length);
        System.arraycopy(suffix,       0, body, prefix.length + txnDataBytes.length,   suffix.length);

        return new HsmWireMessage(header, "KQ", body, null);
    }

    // =====================================================================
    // JA — Generate a Random PIN, Core Host Commands p.207
    // Body: AccountNumber(12 N, rightmost 12 excl check) + PINLength(2 N, 04-12, optional)
    // Response JB: ErrCode(2) + PIN encrypted under LMK (L digits, or 'J'+32H for AES LMK)
    // =====================================================================

    public static HsmWireMessage buildJA(HsmHeader header, Map<String, Object> params) {
        String acct   = (String) params.getOrDefault("accountNo", params.getOrDefault("pan", "000000000000"));
        String acct12 = acct.length() > 12 ? acct.substring(acct.length() - 13, acct.length() - 1) : acct;
        int pinLenVal = Integer.parseInt((String) params.getOrDefault("pinLen", "4"));
        String pinLen = String.format("%02d", pinLenVal);
        String body   = acct12 + pinLen;
        return new HsmWireMessage(header, "JA", body.getBytes(StandardCharsets.US_ASCII), null);
    }

    // =====================================================================
    // DG — Generate VISA PVV, Core Host Commands
    // Wire: PVK(scheme+hex) + PINUnderLMK + PAN(12N) + PVKI(1N). No key-type prefix.
    // Response DH: ErrCode(2) + PVV(4N)
    // =====================================================================

    public static HsmWireMessage buildDG(HsmHeader header, Map<String, Object> params) {
        String pvkScheme    = (String) params.getOrDefault("pvkScheme", "U");
        String pvkHex       = ((String) params.get("pvkHex")).toUpperCase();
        String pinUnderLmk  = ((String) params.get("pinUnderLmk")).toUpperCase();
        String pan          = (String) params.get("pan");
        String pvki         = (String) params.getOrDefault("pvki", "1");
        String pan12 = pan.length() > 12 ? pan.substring(pan.length() - 13, pan.length() - 1) : pan;
        String body = pvkScheme + pvkHex + pinUnderLmk + pan12 + pvki;
        return new HsmWireMessage(header, "DG", body.getBytes(StandardCharsets.US_ASCII), null);
    }

    // =====================================================================
    // DE — Generate IBM PIN Offset, Core Host Commands
    // Wire: PVK(scheme+hex) + PINUnderLMK + CheckLen(2N) + PAN(12N)
    //     + DecimTable(16H) + PINValidData(12N). No key-type prefix.
    // Response DF: ErrCode(2) + Offset(12N)
    // =====================================================================

    public static HsmWireMessage buildDE(HsmHeader header, Map<String, Object> params) {
        String pvkScheme   = (String) params.getOrDefault("pvkScheme", "U");
        String pvkHex      = ((String) params.get("pvkHex")).toUpperCase();
        String pinUnderLmk = ((String) params.get("pinUnderLmk")).toUpperCase();
        String checkLen    = String.format("%02d", Integer.parseInt((String) params.getOrDefault("checkLen", "4")));
        String decimTable  = (String) params.getOrDefault("decimTable", "0123456789012345");
        String pan         = (String) params.get("pan");
        String pan12 = pan.length() > 12 ? pan.substring(pan.length() - 13, pan.length() - 1) : pan;
        String pinValidData = (String) params.getOrDefault("pinValidData", pan12);
        String body = pvkScheme + pvkHex + pinUnderLmk
                    + checkLen + pan12 + decimTable.toUpperCase() + pinValidData.toUpperCase();
        return new HsmWireMessage(header, "DE", body.getBytes(StandardCharsets.US_ASCII), null);
    }

    // =====================================================================
    // DC — Verify Terminal PIN (VISA PVV), p.262
    // Body: TPKType(3H) + PVKType(3H) + MaxPIN(2N)
    //     + PVKScheme(1A)+PVK(hex) + TPKScheme(1A)+TPK(hex)
    //     + PINBlock(16H) + Fmt(2N) + PAN(12N) + PVKI(1N) + PVV(4N)
    // Response DD: ErrCode(2)
    // =====================================================================

    public static HsmWireMessage buildDC(HsmHeader header, Map<String, Object> params) {
        String tpkType   = (String) params.getOrDefault("tpkKeyType", "008");
        String pvkType   = (String) params.getOrDefault("pvkKeyType", "001");
        String maxPin    = (String) params.getOrDefault("maxPinLen", "12");
        String pvkScheme = (String) params.getOrDefault("pvkScheme", "U");
        String pvkHex    = ((String) params.get("pvkHex")).toUpperCase();
        String tpkScheme = (String) params.getOrDefault("tpkScheme", "U");
        String tpkHex    = ((String) params.get("tpkHex")).toUpperCase();
        String pinBlock  = ((String) params.get("pinBlock")).toUpperCase();
        String fmt       = (String) params.getOrDefault("pinBlockFormat", "01");
        String pan       = (String) params.get("pan");
        String pvki      = (String) params.getOrDefault("pvki", "1");
        String pvv       = ((String) params.get("pvv")).toUpperCase();
        String pan12 = pan.length() > 12 ? pan.substring(pan.length() - 13, pan.length() - 1) : pan;
        String body = tpkType + pvkType + maxPin
                    + pvkScheme + pvkHex + tpkScheme + tpkHex
                    + pinBlock + fmt + pan12 + pvki + pvv;
        return new HsmWireMessage(header, "DC", body.getBytes(StandardCharsets.US_ASCII), null);
    }

    // =====================================================================
    // EA — Verify Interchange PIN (IBM 3624 offset), Core Host Commands
    // Wire: ZPK(scheme+hex) + PVK(scheme+hex) + MaxPINLen(2N) + PINBlock(16H)
    //     + Fmt(2N) + CheckLen(2N) + PAN(12N) + DecimTable(16H) + PINValidData(12N)
    //     + Offset(12N). No key-type prefixes. (Input PIN block is under a ZPK; the
    //     gateway carries the ZPK in the tpkScheme/tpkHex params.)
    // Response EB: ErrCode(2)
    // =====================================================================

    public static HsmWireMessage buildEA(HsmHeader header, Map<String, Object> params) {
        String zpkScheme   = (String) params.getOrDefault("tpkScheme", "U");
        String zpkHex      = ((String) params.get("tpkHex")).toUpperCase();
        String pvkScheme   = (String) params.getOrDefault("pvkScheme", "U");
        String pvkHex      = ((String) params.get("pvkHex")).toUpperCase();
        String maxPin      = (String) params.getOrDefault("maxPinLen", "12");
        String pinBlock    = ((String) params.get("pinBlock")).toUpperCase();
        String fmt         = (String) params.getOrDefault("pinBlockFormat", "01");
        String checkLen    = String.format("%02d", Integer.parseInt((String) params.getOrDefault("checkLen", "4")));
        String pan         = (String) params.get("pan");
        String pan12       = pan.length() > 12 ? pan.substring(pan.length() - 13, pan.length() - 1) : pan;
        String dectab      = (String) params.getOrDefault("dectab", "0123456789012345");
        String validation  = (String) params.getOrDefault("pinValidationData", pan12);
        String offset      = (String) params.getOrDefault("pinOffset", "000000000000");
        String body = zpkScheme + zpkHex + pvkScheme + pvkHex + maxPin
                    + pinBlock + fmt + checkLen + pan12
                    + dectab.toUpperCase() + validation.toUpperCase() + offset.toUpperCase();
        return new HsmWireMessage(header, "EA", body.getBytes(StandardCharsets.US_ASCII), null);
    }

    // =====================================================================
    // EC — Verify Interchange PIN (VISA PVV), Core Host Commands
    // Wire: ZPK(scheme+hex) + PVK(scheme+hex) + PINBlock(16H) + Fmt(2N)
    //     + PAN(12N) + PVKI(1N) + PVV(4N). No key-type prefixes, no MaxPINLen.
    // Response ED: ErrCode(2)
    // =====================================================================

    public static HsmWireMessage buildEC(HsmHeader header, Map<String, Object> params) {
        String zpkScheme = (String) params.getOrDefault("tpkScheme", "U");
        String zpkHex    = ((String) params.get("tpkHex")).toUpperCase();
        String pvkScheme = (String) params.getOrDefault("pvkScheme", "U");
        String pvkHex    = ((String) params.get("pvkHex")).toUpperCase();
        String pinBlock  = ((String) params.get("pinBlock")).toUpperCase();
        String fmt       = (String) params.getOrDefault("pinBlockFormat", "01");
        String pan       = (String) params.get("pan");
        String pvki      = (String) params.getOrDefault("pvki", "1");
        String pvv       = ((String) params.get("pvv")).toUpperCase();
        String pan12 = pan.length() > 12 ? pan.substring(pan.length() - 13, pan.length() - 1) : pan;
        String body = zpkScheme + zpkHex + pvkScheme + pvkHex
                    + pinBlock + fmt + pan12 + pvki + pvv;
        return new HsmWireMessage(header, "EC", body.getBytes(StandardCharsets.US_ASCII), null);
    }

    // =====================================================================
    // CC — Translate PIN ZPK→ZPK, Core Host Commands
    // Wire: SrcZPK(scheme+hex) + DstZPK(scheme+hex) + MaxPINLen(2N)
    //     + SrcPINBlock(16H) + SrcFmt(2N) + DstFmt(2N) [+ PAN(12N) for ISO-0]
    // Response CD: ErrCode(2) + PINBlock(16H) + DstFmt(2)
    // For ISO-0 (format 01) the HSM needs the PAN to recover the PIN, so it is
    // appended when supplied. Drop it (omit `pan`) for PAN-less formats.
    // =====================================================================

    public static HsmWireMessage buildCC(HsmHeader header, Map<String, Object> params) {
        String srcScheme = (String) params.getOrDefault("srcZpkScheme", "U");
        String srcHex    = ((String) params.get("srcZpkHex")).toUpperCase();
        String dstScheme = (String) params.getOrDefault("dstZpkScheme", "U");
        String dstHex    = ((String) params.get("dstZpkHex")).toUpperCase();
        String maxPin    = (String) params.getOrDefault("maxPinLen", "12");
        String pinBlock  = ((String) params.get("pinBlock")).toUpperCase();
        String srcFmt    = (String) params.getOrDefault("pinBlockFormat", "01");
        String dstFmt    = (String) params.getOrDefault("dstPinBlockFormat", srcFmt);
        String body = srcScheme + srcHex + dstScheme + dstHex + maxPin + pinBlock + srcFmt + dstFmt;
        if (params.get("pan") != null) {
            String pan = (String) params.get("pan");
            String pan12 = pan.length() > 12 ? pan.substring(pan.length() - 13, pan.length() - 1) : pan;
            body = body + pan12;
        }
        return new HsmWireMessage(header, "CC", body.getBytes(StandardCharsets.US_ASCII), null);
    }

    // =====================================================================
    // BA — Encrypt a Clear PIN (under LMK), Core Host Commands p.240
    // Body: PIN(L H, clear PIN left-justified padded with 'F' to max PIN length L)
    //     + AccountNumber(12 N, rightmost 12 digits excl check)
    // Response BB: ErrCode(2) + PIN encrypted under LMK (L digits, or 'J'+32H for AES LMK)
    // NOTE: this command does NOT use a ZPK and does NOT form a PIN block — the clear
    // PIN is encrypted directly under the LMK. L is the HSM "PIN Length" security
    // setting (CS console, range 5-13); pass `maxPinLen` to match (default 12).
    // =====================================================================

    public static HsmWireMessage buildBA(HsmHeader header, Map<String, Object> params) {
        String clearPin = (String) params.get("clearPin");
        // L = HSM "PIN field length" (CS console, range 5-13). This deployment's HSM = 13.
        int maxPinLen   = Integer.parseInt((String) params.getOrDefault("maxPinLen", "13"));
        StringBuilder pinField = new StringBuilder(clearPin.toUpperCase());
        while (pinField.length() < maxPinLen) pinField.append('F');
        // Account Number: 12 right-most digits, excluding the check digit
        String acct   = (String) params.getOrDefault("accountNo", params.get("pan"));
        String acct12 = acct.length() > 12 ? acct.substring(acct.length() - 13, acct.length() - 1) : acct;
        String body = pinField + acct12;
        return new HsmWireMessage(header, "BA", body.getBytes(StandardCharsets.US_ASCII), null);
    }

    // =====================================================================
    // EE — Derive PIN from IBM Offset, p.270
    // Body: PVKScheme(1A)+PVK(hex) + Offset(12H) + CheckLen(2N)
    //     + AccountNo(12N) + DecimTable(16H) + PINValidData(12N)
    // Response EF: ErrCode(2) + PINLen(2N) + PIN(variable hex)
    // =====================================================================

    public static HsmWireMessage buildEE(HsmHeader header, Map<String, Object> params) {
        String pvkScheme   = (String) params.getOrDefault("pvkScheme", "U");
        String pvkHex      = ((String) params.get("pvkHex")).toUpperCase();
        String offset      = ((String) params.get("offset")).toUpperCase();
        String checkLen    = String.format("%02d", Integer.parseInt((String) params.getOrDefault("checkLen", "4")));
        String accountNo   = (String) params.getOrDefault("accountNo", "000000000000");
        String decimTable  = (String) params.getOrDefault("decimTable", "0123456789012345");
        String pinValidData = (String) params.get("pinValidData");
        String body = pvkScheme + pvkHex + offset.toUpperCase() + checkLen + accountNo
                    + decimTable.toUpperCase() + pinValidData.toUpperCase();
        return new HsmWireMessage(header, "EE", body.getBytes(StandardCharsets.US_ASCII), null);
    }

    // =====================================================================
    // M6 — Generate a MAC, Core Host Commands p.359
    // Body: Mode(1N) + InputFmt(1N) + MacSize(1N) + MacAlg(1N) + Padding(1N) + KeyType(3H)
    //     + KeyScheme(1A)+Key(hex) + [IV(16H) if mode=2 or 3] + MsgLen(4H) + Message(binary)
    // Response M7: ErrCode(2) + MAC(8 or 16 H)
    // MacSize: 0=8 hex, 1=16 hex. MacAlg: 1=ISO9797-1, 3=ISO9797-3(X9.19), 5=CBC-MAC, 6=CMAC.
    // KeyType for Variant LMK: 003=TAK, 008=ZAK. MsgLen is 4 hex (byte count); Message raw binary.
    // =====================================================================

    public static HsmWireMessage buildM6(HsmHeader header, Map<String, Object> params) {
        String mode      = (String) params.getOrDefault("mode", "0");
        String inputFmt  = (String) params.getOrDefault("inputFormat", "0");
        String macSize   = (String) params.getOrDefault("macSize", "1");
        String alg       = (String) params.getOrDefault("algorithm", "3");
        String padding   = (String) params.getOrDefault("padding", "1");
        String keyType   = (String) params.getOrDefault("keyType", "003");
        String keyScheme = (String) params.getOrDefault("keyScheme", "U");
        String keyHex    = ((String) params.get("keyHex")).toUpperCase();
        String dataHex   = ((String) params.get("dataHex")).toUpperCase();
        String iv        = ((String) params.getOrDefault("iv", "0000000000000000")).toUpperCase();

        byte[] dataBytes = java.util.HexFormat.of().parseHex(dataHex);
        String msgLen    = String.format("%04X", dataBytes.length);

        String header2 = mode + inputFmt + macSize + alg + padding + keyType + keyScheme + keyHex;
        byte[] prefixBytes;
        if ("2".equals(mode) || "3".equals(mode)) {
            prefixBytes = (header2 + iv + msgLen).getBytes(StandardCharsets.US_ASCII);
        } else {
            prefixBytes = (header2 + msgLen).getBytes(StandardCharsets.US_ASCII);
        }

        byte[] body = new byte[prefixBytes.length + dataBytes.length];
        System.arraycopy(prefixBytes, 0, body, 0, prefixBytes.length);
        System.arraycopy(dataBytes,   0, body, prefixBytes.length, dataBytes.length);
        return new HsmWireMessage(header, "M6", body, null);
    }

    // =====================================================================
    // M8 — Verify a MAC, Core Host Commands p.363
    // Same field layout as M6 (incl. MacSize + MacAlg) + MAC at end.
    // Response M9: ErrCode(2) — 00=verified, 01=verify fail.
    // =====================================================================

    public static HsmWireMessage buildM8(HsmHeader header, Map<String, Object> params) {
        String mode      = (String) params.getOrDefault("mode", "0");
        String inputFmt  = (String) params.getOrDefault("inputFormat", "0");
        String macSize   = (String) params.getOrDefault("macSize", "1");
        String alg       = (String) params.getOrDefault("algorithm", "3");
        String padding   = (String) params.getOrDefault("padding", "1");
        String keyType   = (String) params.getOrDefault("keyType", "003");
        String keyScheme = (String) params.getOrDefault("keyScheme", "U");
        String keyHex    = ((String) params.get("keyHex")).toUpperCase();
        String dataHex   = ((String) params.get("dataHex")).toUpperCase();
        String mac       = ((String) params.get("mac")).toUpperCase();
        String iv        = ((String) params.getOrDefault("iv", "0000000000000000")).toUpperCase();

        byte[] dataBytes = java.util.HexFormat.of().parseHex(dataHex);
        String msgLen    = String.format("%04X", dataBytes.length);

        String header2 = mode + inputFmt + macSize + alg + padding + keyType + keyScheme + keyHex;
        byte[] prefixBytes;
        if ("2".equals(mode) || "3".equals(mode)) {
            prefixBytes = (header2 + iv + msgLen).getBytes(StandardCharsets.US_ASCII);
        } else {
            prefixBytes = (header2 + msgLen).getBytes(StandardCharsets.US_ASCII);
        }
        byte[] macBytes = mac.getBytes(StandardCharsets.US_ASCII);

        byte[] body = new byte[prefixBytes.length + dataBytes.length + macBytes.length];
        System.arraycopy(prefixBytes, 0, body, 0, prefixBytes.length);
        System.arraycopy(dataBytes,   0, body, prefixBytes.length, dataBytes.length);
        System.arraycopy(macBytes,    0, body, prefixBytes.length + dataBytes.length, macBytes.length);
        return new HsmWireMessage(header, "M8", body, null);
    }

    // =====================================================================
    // GC — Export ZPK under ZMK (LMK→ZMK), p.185
    // Body: ZMKScheme(1A)+ZMK(hex) + ZPKScheme(1A)+ZPK(hex)
    // Response GD: ErrCode(2) + ZPKUnderZMK(scheme+hex) + KCV(6H)
    // =====================================================================

    public static HsmWireMessage buildGC(HsmHeader header, Map<String, Object> params) {
        String zmkScheme = (String) params.getOrDefault("zmkScheme", "U");
        String zmkHex    = ((String) params.get("zmkHex")).toUpperCase();
        String zpkScheme = (String) params.getOrDefault("zpkScheme", "U");
        String zpkHex    = ((String) params.get("zpkHex")).toUpperCase();
        String body = zmkScheme + zmkHex + zpkScheme + zpkHex;
        return new HsmWireMessage(header, "GC", body.getBytes(StandardCharsets.US_ASCII), null);
    }

    // =====================================================================
    // JC — Translate PIN TPK→LMK, p.212
    // Body: KeyType(3H) + KeyScheme(1A)+Key(hex) + MaxPIN(2N)
    //     + PINBlock(16H) + Fmt(2N) + PAN(12N)
    // Response JD: ErrCode(2) + PINLen(2N) + PINUnderLMK(16H)
    // =====================================================================

    public static HsmWireMessage buildJC(HsmHeader header, Map<String, Object> params) {
        String keyType   = (String) params.getOrDefault("keyType", "008");
        String keyScheme = (String) params.getOrDefault("keyScheme", "U");
        String keyHex    = ((String) params.get("keyHex")).toUpperCase();
        String maxPin    = (String) params.getOrDefault("maxPinLen", "12");
        String pinBlock  = ((String) params.get("pinBlock")).toUpperCase();
        String fmt       = (String) params.getOrDefault("pinBlockFormat", "01");
        String pan       = (String) params.get("pan");
        String pan12 = pan.length() > 12 ? pan.substring(pan.length() - 13, pan.length() - 1) : pan;
        String body = keyType + keyScheme + keyHex + maxPin + pinBlock + fmt + pan12;
        return new HsmWireMessage(header, "JC", body.getBytes(StandardCharsets.US_ASCII), null);
    }

    // =====================================================================
    // JE — Translate PIN ZPK→LMK, Core Host Commands
    // Wire: ZPK(scheme+hex) + PINBlock(16H) + Fmt(2N) + PAN(12N).
    // No key-type prefix, no MaxPINLen. Response JF: ErrCode(2) + PINLen(2N) + PINUnderLMK
    // =====================================================================

    public static HsmWireMessage buildJE(HsmHeader header, Map<String, Object> params) {
        String keyScheme = (String) params.getOrDefault("keyScheme", "U");
        String keyHex    = ((String) params.get("keyHex")).toUpperCase();
        String pinBlock  = ((String) params.get("pinBlock")).toUpperCase();
        String fmt       = (String) params.getOrDefault("pinBlockFormat", "01");
        String pan       = (String) params.get("pan");
        String pan12 = pan.length() > 12 ? pan.substring(pan.length() - 13, pan.length() - 1) : pan;
        String body = keyScheme + keyHex + pinBlock + fmt + pan12;
        return new HsmWireMessage(header, "JE", body.getBytes(StandardCharsets.US_ASCII), null);
    }

    // =====================================================================
    // JG — Translate PIN LMK→ZPK (encrypt under ZPK), Core Host Commands
    // Wire: ZPK(scheme+hex) + Fmt(2N) + PAN(12N) + PINUnderLMK.
    // No PIN length and no key-type prefix. Response JH: ErrCode(2) + PINBlock(16H)
    // =====================================================================

    public static HsmWireMessage buildJG(HsmHeader header, Map<String, Object> params) {
        String zpkScheme   = (String) params.getOrDefault("zpkScheme", "U");
        String zpkHex      = ((String) params.get("zpkHex")).toUpperCase();
        String fmt         = (String) params.getOrDefault("pinBlockFormat", "01");
        String pan         = (String) params.get("pan");
        String pan12 = pan.length() > 12 ? pan.substring(pan.length() - 13, pan.length() - 1) : pan;
        String pinUnderLmk = ((String) params.get("pinUnderLmk")).toUpperCase();
        String body = zpkScheme + zpkHex + fmt + pan12 + pinUnderLmk;
        return new HsmWireMessage(header, "JG", body.getBytes(StandardCharsets.US_ASCII), null);
    }

    // =====================================================================
    // NO — HSM Status, p.340
    // Body: (empty)
    // Response NP: ErrCode(2) + LmkCheckValue(16H) + Firmware(8A) + DspFw(4A) + Seq(4H) + Flags(1A)
    // =====================================================================

    public static HsmWireMessage buildNO(HsmHeader header, Map<String, Object> params) {
        return new HsmWireMessage(header, "NO", new byte[0], null);
    }

    // NC — Network Connectivity Check, p.337
    // Body: (empty)
    // Response ND: ErrCode(2)
    public static HsmWireMessage buildNC(HsmHeader header, Map<String, Object> params) {
        return new HsmWireMessage(header, "NC", new byte[0], null);
    }

    // =====================================================================
    // B2 — Echo / Loopback, p.75
    // Body: arbitrary data
    // Response B3: ErrCode(2) + same data echoed back
    // =====================================================================

    public static HsmWireMessage buildB2(HsmHeader header, Map<String, Object> params) {
        String data = (String) params.getOrDefault("data", "PING");
        return new HsmWireMessage(header, "B2", data.getBytes(StandardCharsets.US_ASCII), null);
    }

    // =====================================================================
    // A2 — Generate Key Component (clear), p.44
    // Body: Scheme(1A) — optional, defaults to 'U'
    // Response A3: ErrCode(2) + Scheme(1A) + Component(hex per scheme)
    // =====================================================================

    public static HsmWireMessage buildA2(HsmHeader header, Map<String, Object> params) {
        String scheme = (String) params.getOrDefault("scheme", "U");
        return new HsmWireMessage(header, "A2", scheme.getBytes(StandardCharsets.US_ASCII), null);
    }

    // =====================================================================
    // A4 — Form Key from Encrypted Components, p.50
    // Body: NumComponents(1N) + KeyType(3H) + SchemeLMK(1A) + Component1(scheme+hex) + Component2...
    // Response A5: ErrCode(2) + KeyUnderLMK(scheme+hex) + KCV(6H)
    // =====================================================================

    public static HsmWireMessage buildA4(HsmHeader header, Map<String, Object> params) {
        @SuppressWarnings("unchecked")
        java.util.List<String> components = (java.util.List<String>) params.get("components");
        String keyType  = (String) params.getOrDefault("keyType", "001");
        String scheme   = (String) params.getOrDefault("scheme", "U");
        int numComp = components.size();
        StringBuilder body = new StringBuilder();
        body.append(numComp);
        body.append(keyType);
        body.append(scheme);
        for (String comp : components) {
            body.append(comp.toUpperCase());
        }
        return new HsmWireMessage(header, "A4", body.toString().getBytes(StandardCharsets.US_ASCII), null);
    }

    // =====================================================================
    // BU — Generate Key Check Value, p.102
    // Body: KeyType(3H) + Key(scheme+hex)
    // Response BV: ErrCode(2) + CheckValue(6H)
    // =====================================================================

    public static HsmWireMessage buildBU(HsmHeader header, Map<String, Object> params) {
        String keyType  = (String) params.getOrDefault("keyType", "001");   // 3-digit Key Type Code
        String scheme   = (String) params.getOrDefault("scheme", "U");
        String keyHex   = ((String) params.get("keyHex")).toUpperCase();
        // Key Length Flag (1N): 0=single, 1=double (U), 2=triple (T), 3=HMAC
        String lenFlag  = switch (scheme) { case "U" -> "1"; case "T" -> "2"; default -> "0"; };
        // 2-digit Key Type Code 'FF' => the 3-digit code is supplied after the ';' delimiter.
        // Order per manual: KeyTypeCode2(FF) + KeyLengthFlag + Key(scheme+hex) + ';' + KeyTypeCode3
        String body = "FF" + lenFlag + scheme + keyHex + ";" + keyType;
        return new HsmWireMessage(header, "BU", body.getBytes(StandardCharsets.US_ASCII), null);
    }

    // =====================================================================
    // KW — Verify ARQC / Generate ARPC (EMV 4.x), p.458
    // Same wire format as KQ
    // Body: KeyType(3H) + Key(scheme+hex) + PAN(12N) + PSN(2N) + ARQC(16H)
    //     + TxnDataLen(4H) + TxnData(raw binary) + ARC(4H)
    // Response KX: ErrCode(2) + ARPC(16H)
    // =====================================================================

    public static HsmWireMessage buildKW(HsmHeader header, Map<String, Object> params) {
        // Delegate to same construction as KQ, just change command code
        HsmWireMessage kqMsg = buildKQ(header, params);
        // Re-wrap with KW command code
        return new HsmWireMessage(header, "KW", kqMsg.body(), null);
    }

    // =====================================================================
    // LQ — Generate HMAC on Block of Data (SPA2 AAV generation), p.179
    // Body: HashID(2N) + HMACLen(4N) + KeyType(3H) + Scheme(1A) + KeyHex(N)
    //     + ';' + DataLen(5N) + Data(raw binary)
    // Response LR: ErrCode(2) + HMACLen(4N) + HMAC(hex)
    // =====================================================================

    public static HsmWireMessage buildLQ(HsmHeader header, Map<String, Object> params) {
        String hashId    = (String) params.getOrDefault("hashId", "06");      // 06=SHA-256
        String hmacLen   = (String) params.getOrDefault("hmacLen", "0020");   // 32 bytes
        String keyType   = (String) params.getOrDefault("keyType", "10F");
        String keyScheme = (String) params.getOrDefault("keyScheme", "U");
        String keyHex    = ((String) params.get("keyHex")).toUpperCase();
        String dataHex   = ((String) params.get("dataHex")).toUpperCase();

        byte[] dataBytes = java.util.HexFormat.of().parseHex(dataHex);
        int dataLen = dataBytes.length;
        String dataLenStr = String.format("%05d", dataLen);

        byte[] prefix = (hashId + hmacLen + keyType + keyScheme + keyHex + ";" + dataLenStr)
                        .getBytes(StandardCharsets.US_ASCII);
        byte[] body = new byte[prefix.length + dataBytes.length];
        System.arraycopy(prefix, 0, body, 0, prefix.length);
        System.arraycopy(dataBytes, 0, body, prefix.length, dataBytes.length);
        return new HsmWireMessage(header, "LQ", body, null);
    }

    // =====================================================================
    // LS — Verify HMAC on Block of Data (SPA2 AAV verify), p.181
    // Body: HashID(2N) + HMACLen(4N) + HMAC(hex, HMACLen*2 chars)
    //     + KeyType(3H) + Scheme(1A) + KeyHex(N)
    //     + ';' + DataLen(5N) + Data(raw binary)
    // Response LT: ErrCode(2) — 00=OK, 01=verify fail
    // =====================================================================

    public static HsmWireMessage buildLS(HsmHeader header, Map<String, Object> params) {
        String hashId    = (String) params.getOrDefault("hashId", "06");
        String hmacToVerify = ((String) params.get("hmac")).toUpperCase();
        int hmacBytes = hmacToVerify.length() / 2;
        String hmacLen   = String.format("%04d", hmacBytes);
        String keyType   = (String) params.getOrDefault("keyType", "10F");
        String keyScheme = (String) params.getOrDefault("keyScheme", "U");
        String keyHex    = ((String) params.get("keyHex")).toUpperCase();
        String dataHex   = ((String) params.get("dataHex")).toUpperCase();

        byte[] dataBytes = java.util.HexFormat.of().parseHex(dataHex);
        int dataLen = dataBytes.length;
        String dataLenStr = String.format("%05d", dataLen);

        byte[] prefix = (hashId + hmacLen + hmacToVerify + keyType + keyScheme + keyHex + ";" + dataLenStr)
                        .getBytes(StandardCharsets.US_ASCII);
        byte[] body = new byte[prefix.length + dataBytes.length];
        System.arraycopy(prefix, 0, body, 0, prefix.length);
        System.arraycopy(dataBytes, 0, body, prefix.length, dataBytes.length);
        return new HsmWireMessage(header, "LS", body, null);
    }

    // =====================================================================
    // PM — Verify Dynamic CVV/CVC (dCVV CVN17), p.252
    // Body: SchemeID(1N) + Version(1N) + KeyType(3H) + Scheme(1A) + KeyHex(N)
    //     + KeyDerivMethod(1A) + PAN(nN) + ';' + Expiry(4N) + SvcCode(3N)
    //     + ATC(6N) + DCVV(3N)
    // Response PN: ErrCode(2) — 00=OK, 01=fail
    // =====================================================================

    public static HsmWireMessage buildPM(HsmHeader header, Map<String, Object> params) {
        String schemeId  = (String) params.getOrDefault("schemeId", "0"); // 0=Visa
        String version   = (String) params.getOrDefault("version", "0");  // 0=dCVV
        String keyType   = (String) params.getOrDefault("keyType", "10F");
        String keyScheme = (String) params.getOrDefault("keyScheme", "U");
        String keyHex    = ((String) params.get("keyHex")).toUpperCase();
        String derivMethod = (String) params.getOrDefault("keyDerivMethod", "A");
        String pan       = (String) params.get("pan");
        String expiry    = (String) params.get("expiry");
        String svcCode   = (String) params.getOrDefault("serviceCode", "101");
        String atc       = (String) params.get("atc");
        String dcvv      = (String) params.get("dcvv");

        String body = schemeId + version + keyType + keyScheme + keyHex
                    + derivMethod + pan + ";" + expiry + svcCode + atc + dcvv;
        return new HsmWireMessage(header, "PM", body.getBytes(StandardCharsets.US_ASCII), null);
    }

    // =====================================================================
    // RY — Calculate (mode=3) or Verify (mode=4) Card Security Code, p.257
    // Body: Mode(1N) + Flag(1N: 0=CSC1,2=CSC2,3=AEVV)
    //     + KeyType(3H) + Scheme(1A) + KeyHex(N)
    //     + Account(19N) + Expiry(4N) [+ SvcCode(3N) if flag≠0]
    //     [mode 4 only]: + CSC5(5N) + CSC4(4N) + CSC3(3N)
    // Response RZ: ErrCode(2) + Mode(1N) + values...
    // =====================================================================

    public static HsmWireMessage buildRY(HsmHeader header, Map<String, Object> params) {
        String mode      = (String) params.getOrDefault("mode", "3");
        String flag      = (String) params.getOrDefault("flag", "0");
        String keyType   = (String) params.getOrDefault("keyType", "10F");
        String keyScheme = (String) params.getOrDefault("keyScheme", "U");
        String keyHex    = ((String) params.get("keyHex")).toUpperCase();
        String account   = String.format("%-19s", (String) params.get("account")).replace(' ', '0');
        String expiry    = (String) params.get("expiry");

        StringBuilder body = new StringBuilder();
        body.append(mode).append(flag).append(keyType).append(keyScheme).append(keyHex);
        body.append(account).append(expiry);

        if (!"0".equals(flag)) {
            String svcCode = (String) params.getOrDefault("serviceCode", "000");
            body.append(svcCode);
        }

        if ("4".equals(mode)) {
            body.append((String) params.getOrDefault("csc5", "FFFFF"));
            body.append((String) params.getOrDefault("csc4", "FFFF"));
            body.append((String) params.get("csc3"));
        }

        return new HsmWireMessage(header, "RY", body.toString().getBytes(StandardCharsets.US_ASCII), null);
    }

    // =====================================================================
    // HC — Generate TPK, p.0 (same scheme as A0, pair "008")
    // Body: Scheme(1A)
    // Response HD: ErrCode(2) + Scheme(1A) + KeyHex + KCV(6H)
    // =====================================================================

    public static HsmWireMessage buildHC(HsmHeader header, Map<String, Object> params) {
        String scheme = (String) params.getOrDefault("keyScheme", "U");
        return new HsmWireMessage(header, "HC", scheme.getBytes(StandardCharsets.US_ASCII), null);
    }

    // =====================================================================
    // IA — Generate ZPK, p.0 (same scheme as HC, pair "001")
    // Body: Scheme(1A)
    // Response IB: ErrCode(2) + Scheme(1A) + KeyHex + KCV(6H)
    // =====================================================================

    public static HsmWireMessage buildIA(HsmHeader header, Map<String, Object> params) {
        String scheme = (String) params.getOrDefault("keyScheme", "U");
        return new HsmWireMessage(header, "IA", scheme.getBytes(StandardCharsets.US_ASCII), null);
    }

    // =====================================================================
    // NG — Decrypt an Encrypted PIN, Core Host Commands p.241
    // Body: AccountNumber(12 N, rightmost 12 excl check)
    //     + PIN encrypted under LMK (L digits, or 'J'+32H for AES LMK — the BA/JA output)
    // Response NH: ErrCode(2) + clear PIN (L H, 'F'-padded) + ReferenceNumber(12 N)
    // NOTE: inverse of BA — no ZPK/TPK and no PIN block involved.
    // =====================================================================

    public static HsmWireMessage buildNG(HsmHeader header, Map<String, Object> params) {
        String acct        = (String) params.getOrDefault("accountNo", params.get("pan"));
        String acct12      = acct.length() > 12 ? acct.substring(acct.length() - 13, acct.length() - 1) : acct;
        String pinUnderLmk = ((String) params.get("pinUnderLmk")).toUpperCase();
        String body        = acct12 + pinUnderLmk;
        return new HsmWireMessage(header, "NG", body.getBytes(StandardCharsets.US_ASCII), null);
    }

    // =====================================================================
    // OA — Generate Random Data, p.0
    // Body: Format(1N) + NumBytes(4N)
    // Response OB: ErrCode(2) + Data(hex)
    // =====================================================================

    public static HsmWireMessage buildOA(HsmHeader header, Map<String, Object> params) {
        String format   = (String) params.getOrDefault("format", "0");
        int    numBytes = Integer.parseInt((String) params.getOrDefault("numBytes", "16"));
        String body     = format + String.format("%04d", numBytes);
        return new HsmWireMessage(header, "OA", body.getBytes(StandardCharsets.US_ASCII), null);
    }

    // =====================================================================
    // JS — Translate PIN ZPK→ZPK (variant 2), p.0 (same wire as CC)
    // =====================================================================

    public static HsmWireMessage buildJS(HsmHeader header, Map<String, Object> params) {
        String srcScheme = (String) params.getOrDefault("srcZpkScheme", "U");
        String srcHex    = ((String) params.get("srcZpkHex")).toUpperCase();
        String dstScheme = (String) params.getOrDefault("dstZpkScheme", "U");
        String dstHex    = ((String) params.get("dstZpkHex")).toUpperCase();
        String fmt       = (String) params.getOrDefault("pinBlockFormat", "01");
        String pinBlock  = ((String) params.get("pinBlock")).toUpperCase();
        String dstFlag   = (String) params.getOrDefault("dstFlag", "01");
        String srcFlag   = (String) params.getOrDefault("srcFlag", "01");
        String pan       = (String) params.get("pan");
        String pan12     = pan.length() > 12 ? pan.substring(pan.length() - 13, pan.length() - 1) : pan;
        String body      = srcScheme + srcHex + dstScheme + dstHex + fmt + pinBlock + dstFlag + srcFlag + pan12;
        return new HsmWireMessage(header, "JS", body.getBytes(StandardCharsets.US_ASCII), null);
    }

    // =====================================================================
    // VA — Verify MAC (full-format variant), p.0 (same wire as M8)
    // =====================================================================

    public static HsmWireMessage buildVA(HsmHeader header, Map<String, Object> params) {
        String mode      = (String) params.getOrDefault("mode", "0");
        String inputFmt  = (String) params.getOrDefault("inputFormat", "0");
        String macSize   = (String) params.getOrDefault("macSize", "1");
        String alg       = (String) params.getOrDefault("algorithm", "3");
        String padding   = (String) params.getOrDefault("padding", "1");
        String keyType   = (String) params.getOrDefault("keyType", "003");
        String keyScheme = (String) params.getOrDefault("keyScheme", "U");
        String keyHex    = ((String) params.get("keyHex")).toUpperCase();
        String dataHex   = ((String) params.get("dataHex")).toUpperCase();
        String mac       = ((String) params.get("mac")).toUpperCase();
        String iv        = ((String) params.getOrDefault("iv", "0000000000000000")).toUpperCase();

        byte[] dataBytes = java.util.HexFormat.of().parseHex(dataHex);
        String msgLen    = String.format("%04X", dataBytes.length);

        String hdr2 = mode + inputFmt + macSize + alg + padding + keyType + keyScheme + keyHex;
        byte[] prefixBytes;
        if ("2".equals(mode) || "3".equals(mode)) {
            prefixBytes = (hdr2 + iv + msgLen).getBytes(StandardCharsets.US_ASCII);
        } else {
            prefixBytes = (hdr2 + msgLen).getBytes(StandardCharsets.US_ASCII);
        }
        byte[] macBytes = mac.getBytes(StandardCharsets.US_ASCII);

        byte[] body = new byte[prefixBytes.length + dataBytes.length + macBytes.length];
        System.arraycopy(prefixBytes, 0, body, 0, prefixBytes.length);
        System.arraycopy(dataBytes,   0, body, prefixBytes.length, dataBytes.length);
        System.arraycopy(macBytes,    0, body, prefixBytes.length + dataBytes.length, macBytes.length);
        return new HsmWireMessage(header, "VA", body, null);
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
        int keyHex = KeyScheme.keyTokenLen(s, pos - 1);
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
