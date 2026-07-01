package com.isc.sentinel.vendor.luna;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * X9.143 / ASC X9 TR-31:2018 key-block codec implementing the <b>key-derivation
 * binding method</b> in pure Java (versions B = 3DES, D = AES). No vendor PKCS#11
 * mechanism is used; everything is built from a block cipher (AES/3DES) so it runs
 * anywhere and is verified against Thales luna-kmu known-answer vectors (version D).
 *
 * <p>The KBPK (key-block protection key) wraps a working key into a self-describing,
 * tamper-evident ASCII key block:
 * <pre>  header(16) || hex(ciphertext) || hex(MAC)  </pre>
 *
 * <p>Binding (per X9.143):
 * <ol>
 *   <li>Derive subkeys {@code Kenc,Kmac} from the KBPK via a CMAC-based SP 800-108
 *       counter KDF (8-byte input: counter, usage 0000=enc/0001=mac, 00, algo, key-bits).</li>
 *   <li>Plaintext key field = {@code [2-byte key-length-in-bits][key][random pad]} to a
 *       cipher-block multiple.</li>
 *   <li>{@code MAC = CMAC(Kmac, headerAscii || plaintext)} — this MAC is also the CBC IV
 *       (MAC-then-encrypt).</li>
 *   <li>{@code ciphertext = CBC(Kenc, IV=MAC, plaintext)}.</li>
 * </ol>
 *
 * <p>This class operates on clear KBPK bytes (used as the software reference and KAT).
 * The HSM-backed path performs the same steps with the KBPK resident in the partition.
 */
public final class Tr31Codec {

    private Tr31Codec() {}

    public enum Version {
        B("DESede", "DESede/ECB/NoPadding", "DESede/CBC/NoPadding", 8, (byte) 0x1B, 0x0000, 8),
        D("AES",    "AES/ECB/NoPadding",    "AES/CBC/NoPadding",    16, (byte) 0x87, -1,     16);

        final String keyAlgo, ecb, cbc;
        final int block;       // cipher block size (bytes)
        final byte rb;         // CMAC constant
        final int tdesAlgoId;  // derivation "algorithm" field for 3DES (AES computes it from size)
        final int macLen;      // MAC length in the block (bytes)

        Version(String keyAlgo, String ecb, String cbc, int block, byte rb, int tdesAlgoId, int macLen) {
            this.keyAlgo = keyAlgo; this.ecb = ecb; this.cbc = cbc;
            this.block = block; this.rb = rb; this.tdesAlgoId = tdesAlgoId; this.macLen = macLen;
        }

        static Version of(char c) {
            switch (c) {
                case 'B': return B;
                case 'D': return D;
                default: throw new IllegalArgumentException("unsupported key block version '" + c + "'");
            }
        }
    }

    /** Wrap a working key into a TR-31 key block under the clear KBPK. */
    public static String wrap(Version v, byte[] kbpk, String headerNoLen, byte[] workingKey) throws Exception {
        return wrap(v, kbpk, headerNoLen, workingKey, new SecureRandom());
    }

    /**
     * @param headerNoLen 16-char TR-31 header whose 4-char length field (offset 1..4)
     *                    is a placeholder; this method fills it with the real length.
     */
    public static String wrap(Version v, byte[] kbpk, String headerNoLen, byte[] workingKey, SecureRandom rnd)
            throws Exception {
        // plaintext key field: 2-byte bit length, key, random pad to block multiple
        int bits = workingKey.length * 8;
        int unpadded = 2 + workingKey.length;
        int padded = ((unpadded + v.block - 1) / v.block) * v.block;
        byte[] pt = new byte[padded];
        pt[0] = (byte) (bits >>> 8);
        pt[1] = (byte) bits;
        System.arraycopy(workingKey, 0, pt, 2, workingKey.length);
        byte[] pad = new byte[padded - unpadded];
        rnd.nextBytes(pad);
        System.arraycopy(pad, 0, pt, unpadded, pad.length);

        // total block length = header(16) + 2*ciphertext + 2*mac (hex encoded)
        int total = 16 + pt.length * 2 + v.macLen * 2;
        String header = setLength(headerNoLen, total);

        byte[] kenc = deriveSubkey(v, kbpk, false);
        byte[] kmac = deriveSubkey(v, kbpk, true);

        byte[] macInput = concat(header.getBytes("US-ASCII"), pt);
        byte[] mac = trunc(cmac(v, kmac, macInput), v.macLen);

        byte[] ct = cbcEncrypt(v, kenc, mac, pt);   // IV = MAC
        return header + hex(ct) + hex(mac);
    }

    /** Result of an unwrap: the recovered key plus the parsed header fields. */
    public static final class Unwrapped {
        public final byte[] key;
        public final String header;
        public Unwrapped(byte[] key, String header) { this.key = key; this.header = header; }
    }

    /** Unwrap (and authenticate) a TR-31 key block under the clear KBPK. */
    public static Unwrapped unwrap(byte[] kbpk, String block) throws Exception {
        if (block.length() < 16) throw new IllegalArgumentException("TR-31 block too short");
        Version v = Version.of(block.charAt(0));
        int declared = Integer.parseInt(block.substring(1, 5));
        if (declared != block.length())
            throw new IllegalArgumentException("TR-31 length field " + declared + " != actual " + block.length());

        String header = block.substring(0, 16);
        byte[] rest = unhex(block.substring(16));
        if (rest.length < v.macLen + v.block)
            throw new IllegalArgumentException("TR-31 block body too short");
        int ctLen = rest.length - v.macLen;
        byte[] ct = Arrays.copyOfRange(rest, 0, ctLen);
        byte[] mac = Arrays.copyOfRange(rest, ctLen, rest.length);

        byte[] kenc = deriveSubkey(v, kbpk, false);
        byte[] kmac = deriveSubkey(v, kbpk, true);

        byte[] pt = cbcDecrypt(v, kenc, mac, ct);   // IV = MAC

        byte[] expect = trunc(cmac(v, kmac, concat(header.getBytes("US-ASCII"), pt)), v.macLen);
        if (!constantTimeEquals(expect, mac))
            throw new SecurityException("TR-31 MAC verification failed");

        int bits = ((pt[0] & 0xff) << 8) | (pt[1] & 0xff);
        int keyLen = bits / 8;
        if (keyLen < 0 || 2 + keyLen > pt.length)
            throw new IllegalArgumentException("TR-31 key length field invalid");
        return new Unwrapped(Arrays.copyOfRange(pt, 2, 2 + keyLen), header);
    }

    // ---- SP 800-108 counter KDF (CMAC PRF) ----------------------------------

    private static byte[] deriveSubkey(Version v, byte[] kbpk, boolean mac) throws Exception {
        int outLen = kbpk.length;                 // subkey length = KBPK length
        int bits = outLen * 8;
        int algo = (v == Version.D) ? aesAlgoId(outLen) : v.tdesAlgoId;
        int blocks = (outLen + v.block - 1) / v.block;
        byte[] out = new byte[blocks * v.block];
        for (int i = 0; i < blocks; i++) {
            byte[] in = new byte[8];
            in[0] = (byte) (i + 1);               // counter, 1-based
            in[1] = 0x00;
            in[2] = (byte) (mac ? 0x01 : 0x00);   // usage: enc=0000, mac=0001
            in[3] = 0x00;
            in[4] = (byte) (algo >>> 8);
            in[5] = (byte) algo;
            in[6] = (byte) (bits >>> 8);
            in[7] = (byte) bits;
            byte[] blk = cmac(v, kbpk, in);
            System.arraycopy(blk, 0, out, i * v.block, v.block);
        }
        return Arrays.copyOf(out, outLen);
    }

    private static int aesAlgoId(int keyLen) {
        switch (keyLen) {
            case 16: return 0x0002;
            case 24: return 0x0003;
            case 32: return 0x0004;
            default: throw new IllegalArgumentException("bad AES KBPK length " + keyLen);
        }
    }

    // ---- CMAC (NIST SP 800-38B) over a block cipher -------------------------

    static byte[] cmac(Version v, byte[] key, byte[] msg) throws Exception {
        int b = v.block;
        byte[] l = ecbEncryptBlock(v, key, new byte[b]);
        byte[] k1 = dbl(l, v.rb);
        byte[] k2 = dbl(k1, v.rb);

        int n = (msg.length + b - 1) / b;
        boolean complete;
        if (n == 0) { n = 1; complete = false; }
        else complete = (msg.length % b == 0);

        byte[] last = new byte[b];
        int lastOff = (n - 1) * b;
        if (complete) {
            for (int i = 0; i < b; i++) last[i] = (byte) (msg[lastOff + i] ^ k1[i]);
        } else {
            int rem = msg.length - lastOff;
            for (int i = 0; i < b; i++) {
                byte mi = (i < rem) ? msg[lastOff + i] : (i == rem ? (byte) 0x80 : 0x00);
                last[i] = (byte) (mi ^ k2[i]);
            }
        }

        byte[] x = new byte[b];
        for (int i = 0; i < n - 1; i++) {
            for (int j = 0; j < b; j++) x[j] ^= msg[i * b + j];
            x = ecbEncryptBlock(v, key, x);
        }
        for (int j = 0; j < b; j++) x[j] ^= last[j];
        return ecbEncryptBlock(v, key, x);
    }

    private static byte[] dbl(byte[] in, byte rb) {
        int b = in.length;
        byte[] out = new byte[b];
        int carry = 0;
        for (int i = b - 1; i >= 0; i--) {
            int v = ((in[i] & 0xff) << 1) | carry;
            out[i] = (byte) v;
            carry = (v >>> 8) & 1;
        }
        if (((in[0] & 0x80)) != 0) out[b - 1] ^= rb;
        return out;
    }

    // ---- cipher primitives ---------------------------------------------------

    private static byte[] ecbEncryptBlock(Version v, byte[] key, byte[] block) throws Exception {
        Cipher c = Cipher.getInstance(v.ecb);
        c.init(Cipher.ENCRYPT_MODE, keySpec(v, key));
        return c.doFinal(block);
    }

    private static byte[] cbcEncrypt(Version v, byte[] key, byte[] iv, byte[] data) throws Exception {
        Cipher c = Cipher.getInstance(v.cbc);
        c.init(Cipher.ENCRYPT_MODE, keySpec(v, key), new IvParameterSpec(adjustIv(v, iv)));
        return c.doFinal(data);
    }

    private static byte[] cbcDecrypt(Version v, byte[] key, byte[] iv, byte[] data) throws Exception {
        Cipher c = Cipher.getInstance(v.cbc);
        c.init(Cipher.DECRYPT_MODE, keySpec(v, key), new IvParameterSpec(adjustIv(v, iv)));
        return c.doFinal(data);
    }

    /** The MAC (16B for AES, 8B for 3DES) already matches the cipher block; pass through. */
    private static byte[] adjustIv(Version v, byte[] iv) {
        return iv.length == v.block ? iv : Arrays.copyOf(iv, v.block);
    }

    private static SecretKeySpec keySpec(Version v, byte[] key) {
        if (v == Version.B && key.length == 16) {
            // expand 2-key (K1K2) to 3-key (K1K2K1) for JCE DESede
            byte[] k3 = new byte[24];
            System.arraycopy(key, 0, k3, 0, 16);
            System.arraycopy(key, 0, k3, 16, 8);
            return new SecretKeySpec(k3, "DESede");
        }
        return new SecretKeySpec(key, v.keyAlgo);
    }

    // ---- helpers -------------------------------------------------------------

    private static String setLength(String header, int total) {
        String len = String.format("%04d", total);
        return header.charAt(0) + len + header.substring(5);
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    private static byte[] trunc(byte[] a, int n) { return a.length == n ? a : Arrays.copyOf(a, n); }

    private static boolean constantTimeEquals(byte[] a, byte[] b) {
        if (a.length != b.length) return false;
        int r = 0;
        for (int i = 0; i < a.length; i++) r |= a[i] ^ b[i];
        return r == 0;
    }

    static String hex(byte[] b) {
        StringBuilder s = new StringBuilder(b.length * 2);
        for (byte x : b) s.append(String.format("%02X", x & 0xff));
        return s.toString();
    }

    static byte[] unhex(String s) {
        int n = s.length() / 2;
        byte[] out = new byte[n];
        for (int i = 0; i < n; i++)
            out[i] = (byte) Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16);
        return out;
    }
}
