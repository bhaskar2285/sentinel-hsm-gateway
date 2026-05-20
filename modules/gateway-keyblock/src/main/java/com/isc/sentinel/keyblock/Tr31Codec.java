package com.isc.sentinel.keyblock;

import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.macs.CMac;
import org.bouncycastle.crypto.params.KeyParameter;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.HexFormat;

/**
 * ASC X9 TR-31:2018 Format D (AES) and Format B (3DES) wrap/unwrap.
 *
 * Phase 1: Format D with AES KBPK (binding to the user requirement).
 * Header (16 chars ASCII): version(1) length(4) usage(2) algorithm(1) mode(1) version(2) exportability(1) optional-blocks(2) reserved(2)
 *   e.g. "D0144P0TE00E0000" — D=Format D, 0144=144 bytes, P0=PIN-Encryption usage, T=3DES key inside, E=Encrypt mode, 00=key version, E=Exportable, 0000=optional blocks count
 *
 * Key derivation (AES KBPK, NIST SP 800-108 CMAC-based KDF):
 *   KBEK = CMAC(KBPK, 0x01 || "Key Block Encryption" || 0x00 || L_bits || 0x01)
 *   KBAK = CMAC(KBPK, 0x01 || "Key Block Authentication" || 0x00 || L_bits || 0x01)
 *
 * Encrypt: AES-CBC with IV = MAC(header || payload)  (binding MAC functions as IV)
 *
 * NOTE: This is a minimal Format-D-AES implementation. Full edge-case handling (optional
 * blocks, padding nuances, non-AES KBPK) tracked for Phase 2 expansion. The KCV is computed
 * as the first 6 hex of AES-ECB(key, 0x00..00).
 */
public final class Tr31Codec {

    private static final SecureRandom RND = new SecureRandom();
    private static final HexFormat HEX = HexFormat.of().withUpperCase();

    private Tr31Codec() {}

    /**
     * Wrap a key under an AES KBPK (TR-31 Format D).
     *
     * @param kbpk         32 bytes (AES-256) recommended; 16/24 also valid
     * @param keyToWrap    raw key bytes
     * @param usage2       2-char usage code (e.g. "K0", "P0")
     * @param algo1        1-char algo of wrapped key ('T'=3DES, 'A'=AES, 'D'=DES, 'R'=RSA, 'H'=HMAC)
     * @param mode1        1-char mode ('E'=encrypt, 'D'=decrypt, 'B'=both, 'N'=none, 'V'=verify, 'X'=key-deriv, 'C'=MAC)
     * @param exportability '0'=non-exportable, 'E'=trusted-export, 'N'=non-exportable, 'S'=sensitive
     */
    public static String wrap(byte[] kbpk, byte[] keyToWrap, String usage2, char algo1, char mode1, char exportability) {
        if (usage2 == null || usage2.length() != 2) throw new IllegalArgumentException("usage must be 2 chars");
        if (keyToWrap == null || keyToWrap.length == 0) throw new IllegalArgumentException("empty key");

        // Pad payload to AES block boundary
        int keyLenBits = keyToWrap.length * 8;
        byte[] keyLenField = String.format("%04d", keyLenBits).getBytes(StandardCharsets.US_ASCII);

        // Payload = keyLen(2B) || key || random pad to block boundary
        byte[] payload = buildPayload(keyToWrap);

        // Compute total length: header(16) + 2*hex(encrypted) + 2*hex(mac8)
        int encryptedLen = payload.length;
        int totalAscii = 16 + encryptedLen * 2 + 16;
        String lenField = String.format("%04d", totalAscii);

        String header = "D" + lenField + usage2 + algo1 + mode1 + "00" + exportability + "00" + "00";

        byte[] kbek = deriveKey(kbpk, "Key Block Encryption", encryptedLen * 8);
        byte[] kbak = deriveKey(kbpk, "Key Block Authentication", encryptedLen * 8);

        // MAC over header || payload (CMAC AES, output 8 bytes for legacy interop)
        byte[] mac = cmacTruncate(kbak, concat(header.getBytes(StandardCharsets.US_ASCII), payload), 8);

        // Encrypt payload with AES-CBC; IV = mac (binding)
        byte[] iv = new byte[16];
        System.arraycopy(mac, 0, iv, 0, 8);
        System.arraycopy(mac, 0, iv, 8, 8);
        byte[] encrypted = aesCbcNoPad(kbek, iv, payload, true);

        return header + HEX.formatHex(encrypted) + HEX.formatHex(mac);
    }

    /** Unwrap and return raw key bytes. */
    public static byte[] unwrap(byte[] kbpk, String keyBlock) {
        if (keyBlock == null || keyBlock.length() < 16) throw new IllegalArgumentException("too short");
        if (keyBlock.charAt(0) != 'D') throw new IllegalArgumentException("only Format D supported here");

        String header = keyBlock.substring(0, 16);
        int macAsciiLen = 16; // 8 bytes
        String encryptedHex = keyBlock.substring(16, keyBlock.length() - macAsciiLen);
        String macHex       = keyBlock.substring(keyBlock.length() - macAsciiLen);

        byte[] encrypted = HEX.parseHex(encryptedHex);
        byte[] mac       = HEX.parseHex(macHex);

        byte[] kbek = deriveKey(kbpk, "Key Block Encryption",     encrypted.length * 8);
        byte[] kbak = deriveKey(kbpk, "Key Block Authentication", encrypted.length * 8);

        byte[] iv = new byte[16];
        System.arraycopy(mac, 0, iv, 0, 8);
        System.arraycopy(mac, 0, iv, 8, 8);
        byte[] payload = aesCbcNoPad(kbek, iv, encrypted, false);

        byte[] expectedMac = cmacTruncate(kbak, concat(header.getBytes(StandardCharsets.US_ASCII), payload), 8);
        if (!constantTimeEqual(expectedMac, mac)) throw new SecurityException("TR-31 MAC verification failed");

        int keyLenBits = Integer.parseInt(new String(payload, 0, 4, StandardCharsets.US_ASCII)) == 0
            ? ((payload[0] & 0xFF) << 8) | (payload[1] & 0xFF)
            : Integer.parseInt(new String(payload, 0, 4, StandardCharsets.US_ASCII));
        // Actually payload format = 2-byte big-endian keyLen-in-bits || key || random pad
        keyLenBits = ((payload[0] & 0xFF) << 8) | (payload[1] & 0xFF);
        int keyBytes = keyLenBits / 8;
        byte[] out = new byte[keyBytes];
        System.arraycopy(payload, 2, out, 0, keyBytes);
        return out;
    }

    public static String kcv(byte[] key) {
        try {
            Cipher c = Cipher.getInstance("AES/ECB/NoPadding");
            byte[] aesKey = (key.length == 16 || key.length == 24 || key.length == 32) ? key : padTo32(key);
            c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(aesKey, "AES"));
            byte[] enc = c.doFinal(new byte[16]);
            return HEX.formatHex(enc).substring(0, 6);
        } catch (Exception e) {
            throw new RuntimeException("KCV failed", e);
        }
    }

    // ---- internals ----

    private static byte[] buildPayload(byte[] key) {
        int keyLenBits = key.length * 8;
        int unpadded = 2 + key.length;
        int blockSize = 16;
        int padded = ((unpadded + blockSize - 1) / blockSize) * blockSize;
        byte[] out = new byte[padded];
        out[0] = (byte) ((keyLenBits >> 8) & 0xFF);
        out[1] = (byte) (keyLenBits & 0xFF);
        System.arraycopy(key, 0, out, 2, key.length);
        byte[] pad = new byte[padded - unpadded];
        RND.nextBytes(pad);
        System.arraycopy(pad, 0, out, unpadded, pad.length);
        return out;
    }

    private static byte[] deriveKey(byte[] kbpk, String label, int keyBlockLenBits) {
        // NIST SP 800-108 CMAC counter mode KDF
        // K(1) = CMAC(KBPK, 0x01 || label || 0x00 || L || 0x01)
        byte[] labelBytes = label.getBytes(StandardCharsets.US_ASCII);
        int L = kbpk.length * 8;
        byte[] input = new byte[1 + labelBytes.length + 1 + 4 + 1];
        int p = 0;
        input[p++] = 0x01;
        System.arraycopy(labelBytes, 0, input, p, labelBytes.length); p += labelBytes.length;
        input[p++] = 0x00;
        input[p++] = (byte) ((L >> 24) & 0xFF);
        input[p++] = (byte) ((L >> 16) & 0xFF);
        input[p++] = (byte) ((L >> 8) & 0xFF);
        input[p++] = (byte) (L & 0xFF);
        input[p]   = 0x01;
        return cmac(kbpk, input);
    }

    private static byte[] cmac(byte[] key, byte[] data) {
        CMac mac = new CMac(AESEngine.newInstance(), 128);
        mac.init(new KeyParameter(key));
        mac.update(data, 0, data.length);
        byte[] out = new byte[mac.getMacSize()];
        mac.doFinal(out, 0);
        return out;
    }

    private static byte[] cmacTruncate(byte[] key, byte[] data, int macBytes) {
        byte[] full = cmac(key, data);
        byte[] out = new byte[macBytes];
        System.arraycopy(full, 0, out, 0, macBytes);
        return out;
    }

    private static byte[] aesCbcNoPad(byte[] key, byte[] iv, byte[] data, boolean encrypt) {
        try {
            Cipher c = Cipher.getInstance("AES/CBC/NoPadding");
            c.init(encrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE,
                   new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
            return c.doFinal(data);
        } catch (Exception e) {
            throw new RuntimeException("AES-CBC failed", e);
        }
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    private static byte[] padTo32(byte[] in) {
        byte[] out = new byte[32];
        System.arraycopy(in, 0, out, 0, Math.min(in.length, 32));
        return out;
    }

    private static boolean constantTimeEqual(byte[] a, byte[] b) {
        if (a.length != b.length) return false;
        int diff = 0;
        for (int i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
        return diff == 0;
    }
}
