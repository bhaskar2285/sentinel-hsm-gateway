package com.isc.sentinel.vendor.luna;

import com.isc.sentinel.spi.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * Thales/SafeNet Luna Network HSM adapter — general-purpose PKCS#11 crypto
 * over the JDK {@code SunPKCS11} provider.
 *
 * Scope: Luna is a general crypto HSM, NOT a payment HSM. It performs key
 * generation, data encrypt/decrypt, wrap/unwrap, MAC/HMAC, digest and RNG.
 * Payment primitives (PIN block / PVV / CVV / EMV ARQC / DUKPT / IBM offset)
 * have no PKCS#11 equivalent and return UNSUPPORTED — use the Thales payShield
 * adapter for those.
 *
 * params conventions (GatewayCommand.params):
 *   keyId            token object label (CKA_LABEL) of a stored key
 *   algorithm        JCA algorithm ("AES","DESede","HmacSHA256","AESCMAC","SHA-256",...)
 *   transformation   Cipher transformation ("AES/CBC/PKCS5Padding","AESWrap",...)
 *   keyBits          int key size for generation
 *   label            alias to persist a new / unwrapped key under
 *   data             hex payload
 *   iv               hex IV (generated if absent on encrypt)
 *   mac              hex MAC to verify
 *   wrappingKeyId    label of the KEK for wrap
 *   length           byte count for random
 */
@Slf4j
@Component
public class LunaVendorAdapter implements HsmVendorAdapter {

    private static final Set<OpCode> SUPPORTED = Set.of(
        OpCode.KEY_GEN,
        OpCode.RSA_KEY_GEN,
        OpCode.DATA_ENCRYPT,
        OpCode.DATA_DECRYPT,
        OpCode.KEY_EXPORT,
        OpCode.KEY_FORM_BLOCK,
        OpCode.KEY_IMPORT_RSA_WRAPPED,
        OpCode.KEY_TRANSLATE,
        OpCode.MAC_GEN,
        OpCode.MAC_VERIFY,
        OpCode.HMAC_GEN,
        OpCode.HMAC_VERIFY,
        OpCode.HASH_GEN,
        OpCode.RANDOM_NUM,
        OpCode.RANDOM_DATA,
        OpCode.HSM_STATUS,
        OpCode.HSM_ECHO,
        OpCode.NET_HEALTH,
        // ZMK->DEK custodian ceremony
        OpCode.KEY_FORM_COMPONENTS,
        OpCode.KEY_IMPORT_ZMK
    );

    private final LunaProviderManager luna;

    public LunaVendorAdapter(LunaProviderManager luna) {
        this.luna = luna;
    }

    @Override public HsmVendor vendor() { return HsmVendor.LUNA; }

    @Override public boolean supports(OpCode op) { return SUPPORTED.contains(op); }

    @Override public boolean health(HsmNodeRef node) { return luna.isReady(); }

    @Override
    public GatewayResponse execute(GatewayCommand cmd, HsmNodeRef node) {
        long t0 = System.currentTimeMillis();
        OpCode op = cmd.getOp();
        if (!SUPPORTED.contains(op)) {
            return err(cmd, node, "UNSUPPORTED", "Luna (PKCS#11) cannot perform " + op
                + " — payment primitive; route to Thales payShield");
        }
        if (!luna.isReady()) {
            return err(cmd, node, "OFFLINE", "Luna provider not initialized (" + luna.describe() + ")");
        }
        Map<String, Object> p = cmd.getParams() == null ? Map.of() : cmd.getParams();
        try {
            Map<String, Object> r = switch (op) {
                case KEY_GEN                                   -> genSymmetric(p);
                case RSA_KEY_GEN                               -> genRsa(p);
                case DATA_ENCRYPT                              -> p.containsKey("dekBlob") ? cipherWithDek(p, Cipher.ENCRYPT_MODE) : cipher(p, Cipher.ENCRYPT_MODE);
                case DATA_DECRYPT                              -> p.containsKey("dekBlob") ? cipherWithDek(p, Cipher.DECRYPT_MODE) : cipher(p, Cipher.DECRYPT_MODE);
                case KEY_FORM_COMPONENTS                       -> formZmk(p);
                case KEY_IMPORT_ZMK                            -> importDekUnderZmk(p);
                case KEY_EXPORT, KEY_FORM_BLOCK                -> wrapKey(p);
                case KEY_IMPORT_RSA_WRAPPED, KEY_TRANSLATE     -> unwrapKey(p);
                case MAC_GEN, HMAC_GEN                         -> macGen(p);
                case MAC_VERIFY, HMAC_VERIFY                   -> macVerify(p);
                case HASH_GEN                                  -> digest(p);
                case RANDOM_NUM, RANDOM_DATA                   -> random(p);
                case HSM_STATUS, HSM_ECHO, NET_HEALTH          -> status();
                default -> throw new IllegalStateException("unreachable " + op);
            };
            return ok(cmd, node, r, System.currentTimeMillis() - t0);
        } catch (Exception e) {
            log.warn("Luna op={} failed: {}", op, e.toString());
            return err(cmd, node, "CRYPTO",
                e.getClass().getSimpleName() + ": " + e.getMessage());
        }
    }

    // ---- ZMK -> DEK custodian ceremony ------------------------------------

    /** XOR a list of equal-length hex components into the combined clear key bytes. */
    static byte[] xorHex(java.util.List<String> comps) {
        byte[] acc = hex(comps.get(0));
        for (int i = 1; i < comps.size(); i++) {
            byte[] c = hex(comps.get(i));
            if (c.length != acc.length) throw new IllegalArgumentException("component length mismatch");
            for (int j = 0; j < acc.length; j++) acc[j] ^= c[j];
        }
        return acc;
    }

    /** Uppercase hex of bytes (exposed for tests). */
    static String hexUpper(byte[] b) { return hex(b); }

    /**
     * Payment 3DES keys are double-length (16 bytes, 2-key). JCA "DESede" expects 24 bytes
     * (3-key); a 2-key key is the 3-key form with K3=K1. Expand 16->24 so SecretKeySpec accepts
     * it and the KCV matches a payShield 2-key 3DES KCV. Other lengths/algos pass through.
     */
    static byte[] expandDes3(byte[] clear, String algo) {
        if ("DESede".equals(algo) && clear.length == 16) {
            byte[] out = new byte[24];
            System.arraycopy(clear, 0, out, 0, 16);
            System.arraycopy(clear, 0, out, 16, 8); // K3 = K1
            return out;
        }
        return clear;
    }

    /** Force odd parity on each byte (DES key requirement). DES ignores the parity bit, so the
     *  effective key, KCV and ciphertext are unchanged — this only makes the token accept import. */
    static void oddParity(byte[] k) {
        for (int i = 0; i < k.length; i++) {
            int b = k[i] & 0xFE;
            if (Integer.bitCount(b) % 2 == 0) b |= 1;
            k[i] = (byte) b;
        }
    }

    /**
     * Form a ZMK token object from the XOR of clear custodian components, then store it
     * in the partition. Clear key exists only in this host method (one-time ceremony) and
     * is zeroized in finally. Stock PKCS#11 cannot XOR opaque secret keys inside the HSM.
     */
    @SuppressWarnings("unchecked")
    private Map<String, Object> formZmk(Map<String, Object> p) throws Exception {
        java.util.List<String> comps = (java.util.List<String>) p.get("components");
        if (comps == null || comps.size() < 2) throw new IllegalArgumentException("need >= 2 components");
        String algo = str(p, "algorithm", "DESede");
        String label = require(p, "label");
        byte[] clear = expandDes3(xorHex(comps), algo);
        if ("DESede".equals(algo) || "DES".equals(algo)) oddParity(clear);
        try {
            SecretKey key = new SecretKeySpec(clear, algo);
            luna.keyStore().setKeyEntry(label, key, null, null); // token object, protected by HSM
            Map<String, Object> r = new HashMap<>();
            r.put("keyId", label);
            r.put("algorithm", algo);
            r.put("kcv", kcv(key, algo));
            return r;
        } finally {
            java.util.Arrays.fill(clear, (byte) 0); // zeroize host copy
        }
    }

    /**
     * Validate a DEK delivered already wrapped under the ZMK by unwrapping it INSIDE the HSM
     * (C_UnwrapKey) and computing its KCV. The clear DEK never reaches host RAM. The dekBlob
     * itself is persisted by the service layer; this only proves correctness + returns KCV.
     */
    private Map<String, Object> importDekUnderZmk(Map<String, Object> p) throws Exception {
        String zmkLabel = require(p, "zmkLabel");
        byte[] dekBlob = hex(require(p, "dekBlob"));
        String wrapMech = str(p, "wrapMech", "DESede");        // KEK cipher transformation
        String dekAlgo = str(p, "dekAlgorithm", "DESede");
        Key zmk = luna.keyStore().getKey(zmkLabel, null);
        if (zmk == null) throw new IllegalArgumentException("no ZMK for label " + zmkLabel);
        String wrapAlgo = wrapMech.contains("/") ? wrapMech : dekAlgo + "/ECB/NoPadding";
        Key dek = luna.unwrapKey(zmk, wrapAlgo, dekBlob, dekAlgo);   // inside HSM; clear never in host
        Map<String, Object> r = new HashMap<>();
        r.put("algorithm", dekAlgo);
        r.put("kcv", kcv((SecretKey) dek, dekAlgo)); // KCV proves the unwrap produced the expected key
        return r;
    }

    /**
     * Encrypt/decrypt a block by unwrapping the stored dekBlob under the ZMK into an ephemeral
     * session key, running the cipher, then destroying the session key. Clear DEK never in host.
     */
    private Map<String, Object> cipherWithDek(Map<String, Object> p, int mode) throws Exception {
        String zmkLabel = require(p, "zmkLabel");
        byte[] dekBlob = hex(require(p, "dekBlob"));
        String dekAlgo = str(p, "dekAlgorithm", "DESede");
        String xform = str(p, "transformation", "DESede/ECB/NoPadding");
        byte[] data = hex(require(p, "data"));
        Key zmk = luna.keyStore().getKey(zmkLabel, null);
        if (zmk == null) throw new IllegalArgumentException("no ZMK for label " + zmkLabel);

        SecretKey dek = (SecretKey) luna.unwrapKey(zmk, dekAlgo + "/ECB/NoPadding", dekBlob, dekAlgo);
        try {
            Cipher c = Cipher.getInstance(xform, luna.provider());
            byte[] iv = null;
            boolean needsIv = xform.contains("/CBC") || xform.contains("/CTR");
            if (needsIv) {
                int blk = "DESede".equals(dekAlgo) ? 8 : 16;
                iv = (mode == Cipher.ENCRYPT_MODE)
                    ? (p.get("iv") != null ? hex(str(p, "iv", null)) : randomBytes(blk))
                    : hex(require(p, "iv"));
                c.init(mode, dek, new IvParameterSpec(iv));
            } else {
                c.init(mode, dek);
            }
            byte[] out = c.doFinal(data);
            Map<String, Object> r = new HashMap<>();
            if (mode == Cipher.ENCRYPT_MODE) {
                r.put("ciphertext", hex(out));
                if (iv != null) r.put("iv", hex(iv));
            } else {
                r.put("plaintext", hex(out));
            }
            r.put("transformation", xform);
            return r;
        } finally {
            if (dek instanceof javax.security.auth.Destroyable d && !d.isDestroyed()) {
                try { d.destroy(); } catch (Exception ignore) {}
            }
        }
    }

    // ---- ops ---------------------------------------------------------------

    private Map<String, Object> genSymmetric(Map<String, Object> p) throws Exception {
        String algo = str(p, "algorithm", "AES");
        int bits = intv(p, "keyBits", "AES".equals(algo) ? 256 : 192);
        String label = str(p, "label", null);

        KeyGenerator kg = KeyGenerator.getInstance(algo, luna.provider());
        kg.init(bits, new SecureRandom());
        SecretKey key = kg.generateKey();

        Map<String, Object> r = new HashMap<>();
        if (label != null) {
            luna.keyStore().setKeyEntry(label, key, null, null);  // token object
            r.put("keyId", label);
        }
        r.put("algorithm", algo);
        r.put("keyBits", bits);
        r.put("kcv", kcv(key, algo));
        return r;
    }

    private Map<String, Object> genRsa(Map<String, Object> p) throws Exception {
        int bits = intv(p, "modulusBits", intv(p, "keyBits", 2048));
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", luna.provider());
        kpg.initialize(bits);
        KeyPair kp = kpg.generateKeyPair();

        Map<String, Object> r = new HashMap<>();
        r.put("modulusBits", bits);
        r.put("publicKey", Base64.getEncoder().encodeToString(kp.getPublic().getEncoded()));
        r.put("publicKeyFormat", "X.509");
        // Persisting the private key as a token object requires a certificate
        // (KeyStore.setKeyEntry). Returned public key is sufficient for import/verify;
        // private-key persistence is a partition-ceremony concern.
        return r;
    }

    private Map<String, Object> cipher(Map<String, Object> p, int mode) throws Exception {
        String alias = require(p, "keyId");
        String xform = str(p, "transformation", "AES/CBC/PKCS5Padding");
        byte[] data = hex(require(p, "data"));
        Key key = luna.keyStore().getKey(alias, null);
        if (key == null) throw new IllegalArgumentException("no key for label " + alias);

        Cipher c = Cipher.getInstance(xform, luna.provider());
        byte[] iv = null;
        boolean needsIv = xform.contains("/CBC") || xform.contains("/CTR")
                       || xform.contains("/CFB") || xform.contains("/OFB") || xform.contains("/GCM");
        if (needsIv) {
            if (mode == Cipher.ENCRYPT_MODE) {
                String ivHex = str(p, "iv", null);
                int blk = "DESede".equals(key.getAlgorithm()) ? 8 : 16;
                iv = ivHex != null ? hex(ivHex) : randomBytes(blk);
            } else {
                iv = hex(require(p, "iv"));
            }
            c.init(mode, key, new IvParameterSpec(iv));
        } else {
            c.init(mode, key);
        }
        byte[] out = c.doFinal(data);

        Map<String, Object> r = new HashMap<>();
        if (mode == Cipher.ENCRYPT_MODE) {
            r.put("ciphertext", hex(out));
            if (iv != null) r.put("iv", hex(iv));
        } else {
            r.put("plaintext", hex(out));
        }
        r.put("transformation", xform);
        return r;
    }

    private Map<String, Object> wrapKey(Map<String, Object> p) throws Exception {
        String targetAlias = require(p, "keyId");
        String kekAlias = require(p, "wrappingKeyId");
        String xform = str(p, "transformation", "AESWrap");
        Key target = luna.keyStore().getKey(targetAlias, null);
        Key kek = luna.keyStore().getKey(kekAlias, null);
        if (target == null) throw new IllegalArgumentException("no key for label " + targetAlias);
        if (kek == null)    throw new IllegalArgumentException("no KEK for label " + kekAlias);

        Cipher c = Cipher.getInstance(xform, luna.provider());
        c.init(Cipher.WRAP_MODE, kek);
        byte[] wrapped = c.wrap(target);

        Map<String, Object> r = new HashMap<>();
        r.put("wrappedKey", hex(wrapped));
        r.put("transformation", xform);
        return r;
    }

    private Map<String, Object> unwrapKey(Map<String, Object> p) throws Exception {
        String kekAlias = require(p, "wrappingKeyId");
        byte[] wrapped = hex(require(p, "wrappedKey"));
        String xform = str(p, "transformation", "AESWrap");
        String keyAlgo = str(p, "algorithm", "AES");
        String label = str(p, "label", null);
        Key kek = luna.keyStore().getKey(kekAlias, null);
        if (kek == null) throw new IllegalArgumentException("no KEK for label " + kekAlias);

        Cipher c = Cipher.getInstance(xform, luna.provider());
        c.init(Cipher.UNWRAP_MODE, kek);
        Key key = c.unwrap(wrapped, keyAlgo, Cipher.SECRET_KEY);

        Map<String, Object> r = new HashMap<>();
        if (label != null && key instanceof SecretKey sk) {
            luna.keyStore().setKeyEntry(label, sk, null, null);
            r.put("keyId", label);
            r.put("kcv", kcv(sk, keyAlgo));
        }
        r.put("algorithm", keyAlgo);
        return r;
    }

    private Map<String, Object> macGen(Map<String, Object> p) throws Exception {
        String alias = require(p, "keyId");
        String algo = str(p, "algorithm", "HmacSHA256");
        byte[] data = hex(require(p, "data"));
        Key key = luna.keyStore().getKey(alias, null);
        if (key == null) throw new IllegalArgumentException("no key for label " + alias);
        Mac mac = Mac.getInstance(algo, luna.provider());
        mac.init(key);
        byte[] out = mac.doFinal(data);
        Map<String, Object> r = new HashMap<>();
        r.put("mac", hex(out));
        r.put("algorithm", algo);
        return r;
    }

    private Map<String, Object> macVerify(Map<String, Object> p) throws Exception {
        String expected = require(p, "mac").toUpperCase();
        Map<String, Object> g = macGen(p);
        boolean valid = expected.equals(((String) g.get("mac")).toUpperCase());
        Map<String, Object> r = new HashMap<>();
        r.put("valid", valid);
        r.put("algorithm", g.get("algorithm"));
        return r;
    }

    private Map<String, Object> digest(Map<String, Object> p) throws Exception {
        String algo = str(p, "algorithm", "SHA-256");
        byte[] data = hex(require(p, "data"));
        MessageDigest md;
        try { md = MessageDigest.getInstance(algo, luna.provider()); }
        catch (Exception e) { md = MessageDigest.getInstance(algo); }  // digest needs no token
        byte[] out = md.digest(data);
        Map<String, Object> r = new HashMap<>();
        r.put("digest", hex(out));
        r.put("algorithm", algo);
        return r;
    }

    private Map<String, Object> random(Map<String, Object> p) {
        int len = intv(p, "length", 16);
        Map<String, Object> r = new HashMap<>();
        r.put("random", hex(randomBytes(len)));
        r.put("length", len);
        return r;
    }

    private Map<String, Object> status() {
        Map<String, Object> r = new HashMap<>();
        r.put("provider", luna.describe());
        r.put("ready", luna.isReady());
        return r;
    }

    // ---- helpers -----------------------------------------------------------

    /** Thales-style KCV: encrypt a zero block under the key, first 3 bytes. */
    private String kcv(SecretKey key, String algo) {
        try {
            int blk = "DESede".equals(algo) ? 8 : 16;
            Cipher c = Cipher.getInstance(algo + "/ECB/NoPadding", luna.provider());
            c.init(Cipher.ENCRYPT_MODE, key);
            byte[] out = c.doFinal(new byte[blk]);
            return hex(out).substring(0, 6);
        } catch (Exception e) {
            return "------";
        }
    }

    private byte[] randomBytes(int n) {
        byte[] b = new byte[n];
        new SecureRandom().nextBytes(b);
        return b;
    }

    private static String str(Map<String, Object> p, String k, String def) {
        Object v = p.get(k);
        return v == null ? def : String.valueOf(v);
    }

    private static int intv(Map<String, Object> p, String k, int def) {
        Object v = p.get(k);
        if (v == null) return def;
        if (v instanceof Number n) return n.intValue();
        return Integer.parseInt(String.valueOf(v));
    }

    private static String require(Map<String, Object> p, String k) {
        Object v = p.get(k);
        if (v == null || String.valueOf(v).isBlank())
            throw new IllegalArgumentException("missing param: " + k);
        return String.valueOf(v);
    }

    private static byte[] hex(String s) {
        String h = s.trim();
        int n = h.length();
        byte[] b = new byte[n / 2];
        for (int i = 0; i < n; i += 2)
            b[i / 2] = (byte) Integer.parseInt(h.substring(i, i + 2), 16);
        return b;
    }

    private static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) sb.append(String.format("%02X", x));
        return sb.toString();
    }

    private GatewayResponse ok(GatewayCommand cmd, HsmNodeRef node, Map<String, Object> result, long ms) {
        return GatewayResponse.builder()
            .op(cmd.getOp()).vendor(HsmVendor.LUNA)
            .hsmNodeId(node == null ? null : String.valueOf(node.getId()))
            .status("OK").errCode("00").errText(null)
            .latencyMs(ms).result(result).build();
    }

    private GatewayResponse err(GatewayCommand cmd, HsmNodeRef node, String code, String text) {
        return GatewayResponse.builder()
            .op(cmd.getOp()).vendor(HsmVendor.LUNA)
            .hsmNodeId(node == null ? null : String.valueOf(node.getId()))
            .status("ERROR").errCode(code).errText(text)
            .latencyMs(0).result(Map.of()).build();
    }
}
