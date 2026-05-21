package com.isc.sentinel.api.service;

import com.isc.sentinel.api.controller.KeyController.TenantCtx;
import com.isc.sentinel.api.dto.*;
import com.isc.sentinel.core.dispatch.CommandDispatcher;
import com.isc.sentinel.persistence.entity.HsmKey;
import com.isc.sentinel.persistence.repo.HsmKeyRepository;
import com.isc.sentinel.spi.GatewayCommand;
import com.isc.sentinel.spi.GatewayResponse;
import com.isc.sentinel.spi.HsmVendor;
import com.isc.sentinel.spi.OpCode;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class KeyService {

    private final CommandDispatcher dispatcher;
    private final HsmKeyRepository keyRepo;

    public RsaKeyGenResponse generateRsa(RsaKeyGenRequest req, String userId, TenantCtx tenant) {
        Map<String, Object> params = new HashMap<>();
        params.put("keyType", req.getKeyType());
        params.put("modulusBits", req.getModulusBits());
        params.put("encoding", req.getEncoding());
        params.put("publicExponentHex", req.getPublicExponentHex());

        GatewayCommand cmd = GatewayCommand.builder()
            .op(OpCode.RSA_KEY_GEN)
            .vendorHint(HsmVendor.THALES)
            .params(params)
            .userId(userId)
            .build();

        GatewayResponse resp = dispatcher.dispatch(cmd);

        String keyId = null;
        String publicKey = null;
        String kcv = null;
        if ("OK".equals(resp.getStatus())) {
            publicKey = (String) resp.getResult().get("publicKey");
            String privUnderLmk = (String) resp.getResult().get("privateKeyUnderLmk");

            if (privUnderLmk == null || privUnderLmk.isEmpty()) {
                return RsaKeyGenResponse.builder()
                    .status("ERROR").errCode("VL")
                    .errText("EJ returned no privateKeyUnderLmk — HSM did not seal the private key. Not persisting.")
                    .latencyMs(resp.getLatencyMs())
                    .build();
            }

            // KCV for RSA = first 6 hex of SHA-256(publicKeyDER) — fingerprint, public-safe.
            if (publicKey != null) {
                try {
                    byte[] pub = java.util.HexFormat.of().parseHex(publicKey);
                    java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
                    byte[] digest = md.digest(pub);
                    kcv = java.util.HexFormat.of().withUpperCase().formatHex(digest).substring(0, 6);
                } catch (Exception ignored) { /* leave kcv null on parse error */ }
            }

            HsmKey saved = keyRepo.save(HsmKey.builder()
                .keyUuid(UUID.randomUUID())
                .label(req.getLabel())
                .keyType("RSA")
                .algo("RSA")
                .keyLengthBits(req.getModulusBits())
                .usage(req.getUsage())
                .ownerUserId(userId)
                .ownerOrg(req.getOwnerOrg())
                .bankRecId(tenant == null ? null : tenant.bankRecId())
                .branchRecId(tenant == null ? null : tenant.branchRecId())
                .kcv(kcv)
                .vendorOrigin("thales")
                .encryptedBlob(privUnderLmk == null ? null : privUnderLmk.getBytes(StandardCharsets.US_ASCII))
                .status("ACTIVE")
                .version(1)
                .build());
            keyId = saved.getKeyUuid().toString();
        }

        return RsaKeyGenResponse.builder()
            .keyId(keyId)
            .publicKey(publicKey)
            .kcv(kcv)
            .status(resp.getStatus())
            .errCode(resp.getErrCode())
            .errText(resp.getErrText())
            .latencyMs(resp.getLatencyMs())
            .build();
    }

    public SymKeyGenResponse generateSymmetric(SymKeyGenRequest req, String userId, TenantCtx tenant) {
        Map<String, Object> params = new HashMap<>();
        params.put("mode",      req.getMode());
        params.put("keyType",   req.getKeyType());
        params.put("keyScheme", req.getKeyScheme());

        if ("1".equals(req.getMode())) {
            if (req.getZmkKeyId() == null) {
                return SymKeyGenResponse.builder()
                    .status("ERROR").errCode("VL")
                    .errText("zmkKeyId required when mode=1")
                    .build();
            }
            HsmKey zmk = keyRepo.findByKeyUuid(UUID.fromString(req.getZmkKeyId()))
                .orElseThrow(() -> new IllegalArgumentException("ZMK not found: " + req.getZmkKeyId()));
            String blob = new String(zmk.getEncryptedBlob() == null ? new byte[0] : zmk.getEncryptedBlob(), StandardCharsets.US_ASCII);
            if (blob.length() < 2) {
                return SymKeyGenResponse.builder()
                    .status("ERROR").errCode("VL")
                    .errText("ZMK has no LMK-encrypted material")
                    .build();
            }
            params.put("zmkScheme",   blob.substring(0, 1));
            params.put("zmkUnderLmk", blob.substring(1));
            params.put("outScheme",   req.getOutScheme());
        }

        GatewayResponse resp = dispatcher.dispatch(GatewayCommand.builder()
            .op(OpCode.KEY_GEN)
            .vendorHint(HsmVendor.THALES)
            .params(params)
            .userId(userId)
            .build());

        String keyId = null;
        String kcv = null;
        String keyUnderZmk = null;
        if ("OK".equals(resp.getStatus())) {
            String scheme      = (String) resp.getResult().getOrDefault("scheme", req.getKeyScheme());
            String keyUnderLmk = (String) resp.getResult().getOrDefault("keyUnderLmk", "");
            kcv                = (String) resp.getResult().get("kcv");
            keyUnderZmk        = (String) resp.getResult().get("keyUnderZmk");

            if (keyUnderLmk.isEmpty()) {
                return SymKeyGenResponse.builder()
                    .status("ERROR").errCode("VL")
                    .errText("A1 returned empty keyUnderLmk — HSM did not seal the key. Not persisting.")
                    .latencyMs(resp.getLatencyMs())
                    .build();
            }

            String blob = scheme + keyUnderLmk;
            String algo = algoForScheme(scheme);
            int    bits = bitsForScheme(scheme);
            String keyTypeName = keyTypeFamilyName(req.getKeyType());

            HsmKey saved = keyRepo.save(HsmKey.builder()
                .keyUuid(UUID.randomUUID())
                .label(req.getLabel())
                .keyType(keyTypeName)
                .algo(algo)
                .keyLengthBits(bits)
                .usage(req.getUsage())
                .ownerUserId(userId)
                .ownerOrg(req.getOwnerOrg())
                .bankRecId(tenant == null ? null : tenant.bankRecId())
                .branchRecId(tenant == null ? null : tenant.branchRecId())
                .kcv(kcv)
                .vendorOrigin("thales")
                .encryptedBlob(blob.getBytes(StandardCharsets.US_ASCII))
                .status("ACTIVE")
                .version(1)
                .build());
            keyId = saved.getKeyUuid().toString();
        }

        return SymKeyGenResponse.builder()
            .keyId(keyId)
            .kcv(kcv)
            .keyUnderZmk(keyUnderZmk)
            .status(resp.getStatus())
            .errCode(resp.getErrCode())
            .errText(resp.getErrText())
            .latencyMs(resp.getLatencyMs())
            .build();
    }

    private static String algoForScheme(String scheme) {
        if (scheme == null || scheme.isEmpty()) return "3DES";
        return switch (scheme.charAt(0)) {
            case 'R', 'S', 'H' -> "AES";
            default            -> "3DES";
        };
    }

    private static int bitsForScheme(String scheme) {
        if (scheme == null || scheme.isEmpty()) return 128;
        return switch (scheme.charAt(0)) {
            case 'Z'           -> 64;
            case 'U', 'X', 'Y' -> 128;
            case 'T'           -> 192;
            case 'R'           -> 128;
            case 'S'           -> 192;
            case 'H'           -> 256;
            default            -> 128;
        };
    }

    /** Reverse of keyTypeFamilyName: takes a stored key_type name (ZMK/ZPK/...) and
     *  returns the Thales 3-digit family code. Falls back to the request hint then "00A". */
    /** Pad/truncate caller IV to the cipher block size for the given scheme.
     *  3DES → 16 hex (8 bytes), AES → 32 hex (16 bytes). */
    private static String sizeIvForScheme(String iv, String scheme) {
        int target = (scheme != null && !scheme.isEmpty()
                  && (scheme.charAt(0) == 'R' || scheme.charAt(0) == 'S' || scheme.charAt(0) == 'H'))
                ? 32 : 16;
        if (iv.length() == target) return iv;
        if (iv.length() > target)  return iv.substring(0, target);
        return iv + "0".repeat(target - iv.length());
    }

    private static String familyCodeForKeyType(String storedName, String requestHint) {
        if (storedName != null) {
            switch (storedName) {
                case "ZMK":  return "000";
                case "ZPK":  return "001";
                case "KBPK": return "002";
                case "TMK":  return "008";
                case "DATA": return "00A";
                default:     break;
            }
        }
        return requestHint != null ? requestHint : "00A";
    }

    private static String keyTypeFamilyName(String code) {
        if (code == null) return "GENERIC";
        return switch (code) {
            case "000" -> "ZMK";
            case "001" -> "ZPK";
            case "002" -> "KBPK";
            case "008" -> "TMK";
            case "00A" -> "DATA";
            default    -> "GENERIC";
        };
    }

    public KeyImportResponse importRsaWrapped(ImportRsaWrappedRequest req, String userId, TenantCtx tenant) {
        Map<String, Object> params = new HashMap<>();
        params.put("mode", req.getMode());
        params.put("hashId", req.getHashId());
        params.put("wrappingPublicKey", req.getWrappingPublicKey());
        params.put("wrappedKey", req.getWrappedKey());

        GatewayResponse resp = dispatcher.dispatch(GatewayCommand.builder()
            .op(OpCode.KEY_IMPORT_RSA_WRAPPED)
            .vendorHint(HsmVendor.THALES)
            .params(params)
            .userId(userId)
            .build());

        String keyId = null;
        String kcv = null;
        if ("OK".equals(resp.getStatus())) {
            String scheme       = (String) resp.getResult().getOrDefault("scheme", "U");
            String keyUnderLmk  = (String) resp.getResult().getOrDefault("keyUnderLmk", "");
            kcv                 = (String) resp.getResult().get("kcv");

            if (keyUnderLmk.isEmpty()) {
                return KeyImportResponse.builder()
                    .status("ERROR").errCode("VL")
                    .errText("GJ returned empty keyUnderLmk — import did not seal the key. Not persisting.")
                    .latencyMs(resp.getLatencyMs())
                    .build();
            }
            // Persist as scheme+hex (vendor wire format) for later A8 export.
            String blob = scheme + keyUnderLmk;

            HsmKey saved = keyRepo.save(HsmKey.builder()
                .keyUuid(UUID.randomUUID())
                .label(req.getLabel())
                .keyType(req.getKeyType() == null ? "ZPK" : req.getKeyType())
                .algo("3DES")
                .keyLengthBits(128)
                .usage(req.getUsage())
                .ownerUserId(userId)
                .bankRecId(tenant == null ? null : tenant.bankRecId())
                .branchRecId(tenant == null ? null : tenant.branchRecId())
                .kcv(kcv)
                .vendorOrigin("thales")
                .encryptedBlob(blob.getBytes(StandardCharsets.US_ASCII))
                .status("ACTIVE")
                .version(1)
                .build());
            keyId = saved.getKeyUuid().toString();
        }

        return KeyImportResponse.builder()
            .keyId(keyId)
            .kcv(kcv)
            .status(resp.getStatus())
            .errCode(resp.getErrCode())
            .errText(resp.getErrText())
            .latencyMs(resp.getLatencyMs())
            .build();
    }

    public KeyImportResponse importZmkWrapped(ImportZmkWrappedRequest req, String userId, TenantCtx tenant) {
        HsmKey zmk = keyRepo.findByKeyUuid(UUID.fromString(req.getZmkKeyId()))
            .orElseThrow(() -> new IllegalArgumentException("ZMK not found: " + req.getZmkKeyId()));
        String zmkBlob = new String(zmk.getEncryptedBlob() == null ? new byte[0] : zmk.getEncryptedBlob(), StandardCharsets.US_ASCII);
        if (zmkBlob.length() < 2) {
            return KeyImportResponse.builder()
                .status("ERROR").errCode("VL")
                .errText("ZMK has no LMK material — pick a valid ZMK")
                .build();
        }

        Map<String, Object> params = new HashMap<>();
        params.put("keyType",     req.getKeyType());
        params.put("zmkScheme",   zmkBlob.substring(0, 1));
        params.put("zmkUnderLmk", zmkBlob.substring(1));
        params.put("keyScheme",   req.getKeyScheme());
        params.put("keyUnderZmk", req.getKeyUnderZmkHex());
        params.put("lmkScheme",   req.getLmkScheme());

        GatewayResponse resp = dispatcher.dispatch(GatewayCommand.builder()
            .op(OpCode.KEY_IMPORT_ZMK)
            .vendorHint(HsmVendor.THALES)
            .params(params)
            .userId(userId)
            .build());

        String keyId = null;
        String kcv = null;
        if ("OK".equals(resp.getStatus())) {
            String scheme       = (String) resp.getResult().getOrDefault("scheme", req.getLmkScheme());
            String keyUnderLmk  = (String) resp.getResult().getOrDefault("keyUnderLmk", "");
            kcv                 = (String) resp.getResult().get("kcv");

            if (keyUnderLmk.isEmpty()) {
                return KeyImportResponse.builder()
                    .status("ERROR").errCode("VL")
                    .errText("A7 returned empty keyUnderLmk — not persisting.")
                    .latencyMs(resp.getLatencyMs())
                    .build();
            }

            String blob = scheme + keyUnderLmk;
            HsmKey saved = keyRepo.save(HsmKey.builder()
                .keyUuid(UUID.randomUUID())
                .label(req.getLabel())
                .keyType(keyTypeFamilyName(req.getKeyType()))
                .algo(algoForScheme(scheme))
                .keyLengthBits(bitsForScheme(scheme))
                .usage(req.getUsage())
                .ownerUserId(userId)
                .ownerOrg(req.getOwnerOrg())
                .bankRecId(tenant == null ? null : tenant.bankRecId())
                .branchRecId(tenant == null ? null : tenant.branchRecId())
                .kcv(kcv)
                .vendorOrigin("thales")
                .encryptedBlob(blob.getBytes(StandardCharsets.US_ASCII))
                .status("ACTIVE")
                .version(1)
                .build());
            keyId = saved.getKeyUuid().toString();
        }

        return KeyImportResponse.builder()
            .keyId(keyId)
            .kcv(kcv)
            .status(resp.getStatus())
            .errCode(resp.getErrCode())
            .errText(resp.getErrText())
            .latencyMs(resp.getLatencyMs())
            .build();
    }

    public EncryptResponse encrypt(EncryptRequest req, String userId) {
        HsmKey key = keyRepo.findByKeyUuid(UUID.fromString(req.getKeyId()))
            .orElseThrow(() -> new IllegalArgumentException("key not found: " + req.getKeyId()));
        if ("INVALID".equals(key.getStatus())) {
            return EncryptResponse.builder().status("ERROR").errCode("VL")
                .errText("Key is INVALID — regenerate.").build();
        }
        String blob = new String(key.getEncryptedBlob() == null ? new byte[0] : key.getEncryptedBlob(), StandardCharsets.US_ASCII);
        if (blob.length() < 2) {
            return EncryptResponse.builder().status("ERROR").errCode("VL")
                .errText("Key has no LMK material.").build();
        }
        String scheme = blob.substring(0, 1);
        Map<String, Object> params = new HashMap<>();
        params.put("mode",         req.getMode());
        params.put("keyType",      familyCodeForKeyType(key.getKeyType(), req.getKeyType()));
        params.put("keyScheme",    scheme);
        params.put("keyUnderLmk",  blob.substring(1));
        if (req.getIv() != null && !req.getIv().isEmpty()) {
            params.put("iv", sizeIvForScheme(req.getIv(), scheme));
        }
        params.put("plaintextHex", req.getPlaintextHex());

        GatewayResponse resp = dispatcher.dispatch(GatewayCommand.builder()
            .op(OpCode.DATA_ENCRYPT)
            .vendorHint(HsmVendor.THALES)
            .params(params)
            .keyId(req.getKeyId())
            .userId(userId)
            .build());

        return EncryptResponse.builder()
            .ciphertextHex((String) resp.getResult().get("ciphertext"))
            .status(resp.getStatus())
            .errCode(resp.getErrCode())
            .errText(resp.getErrText())
            .latencyMs(resp.getLatencyMs())
            .build();
    }

    public ExportKeyResponse exportKey(String keyId, ExportKeyRequest req, String userId) {
        HsmKey key = keyRepo.findByKeyUuid(UUID.fromString(keyId))
            .orElseThrow(() -> new IllegalArgumentException("key not found: " + keyId));

        if ("INVALID".equals(key.getStatus())) {
            return ExportKeyResponse.builder()
                .keyId(keyId).format(req.getFormat()).status("ERROR").errCode("VL")
                .errText("Key " + keyId + " is INVALID (no LMK material — was created by a failed generation). Regenerate the key.")
                .latencyMs(0).build();
        }

        String keyBlob = new String(key.getEncryptedBlob() == null ? new byte[0] : key.getEncryptedBlob(), StandardCharsets.US_ASCII);

        // Block RSA keys from A8/B4 — those are symmetric-only.
        if ("RSA".equalsIgnoreCase(key.getAlgo()) && !"RAW".equalsIgnoreCase(req.getFormat())) {
            return ExportKeyResponse.builder()
                .keyId(keyId).format(req.getFormat()).status("ERROR").errCode("VL")
                .errText("RSA keys cannot be exported via A8 / TR-31 (symmetric only). Use RAW for the LMK-encrypted DER, or GK (Phase 2) for RSA public-key wrap.")
                .latencyMs(0).build();
        }

        // RAW format: skip HSM, return LMK-encrypted blob directly (admin only)
        if ("RAW".equalsIgnoreCase(req.getFormat())) {
            return ExportKeyResponse.builder()
                .keyId(keyId)
                .format("RAW")
                .keyBlock(keyBlob)
                .kcv(key.getKcv())
                .status("OK")
                .errCode("00")
                .errText("No error (raw LMK blob)")
                .latencyMs(0)
                .build();
        }

        // Resolve wrapping key (ZMK/KBPK/TMK)
        if (req.getKbpkKeyId() == null) {
            return ExportKeyResponse.builder()
                .keyId(keyId)
                .format(req.getFormat())
                .status("ERROR")
                .errCode("VL")
                .errText("kbpkKeyId required for non-RAW exports")
                .latencyMs(0)
                .build();
        }
        HsmKey zmk = keyRepo.findByKeyUuid(UUID.fromString(req.getKbpkKeyId()))
            .orElseThrow(() -> new IllegalArgumentException("KBPK/ZMK not found: " + req.getKbpkKeyId()));

        if (keyBlob.length() < 2) {
            return ExportKeyResponse.builder()
                .keyId(keyId)
                .format(req.getFormat())
                .status("ERROR")
                .errCode("VL")
                .errText("Key " + keyId + " has no LMK material. Regenerate via A0/EI — old row from a failed creation.")
                .latencyMs(0)
                .build();
        }

        String keyScheme = keyBlob.substring(0, 1);
        String keyHex    = keyBlob.substring(1);

        String zmkBlob = new String(zmk.getEncryptedBlob() == null ? new byte[0] : zmk.getEncryptedBlob(), StandardCharsets.US_ASCII);
        if (zmkBlob.length() < 2) {
            return ExportKeyResponse.builder()
                .keyId(keyId)
                .format(req.getFormat())
                .status("ERROR")
                .errCode("VL")
                .errText("Wrapping key has no LMK-encrypted material")
                .latencyMs(0)
                .build();
        }
        String zmkScheme = zmkBlob.substring(0, 1);
        String zmkHex    = zmkBlob.substring(1);

        // Route by format:
        //   TR31_B / TR31_D / X9_143 → B0 (TR-31 / X9.143 key block, HSM-side wrap)
        //   anything else           → A8 (legacy ZMK-wrap, returns scheme+hex)
        boolean isKeyBlock = "TR31_B".equalsIgnoreCase(req.getFormat())
                          || "TR31_D".equalsIgnoreCase(req.getFormat())
                          || "X9_143".equalsIgnoreCase(req.getFormat());

        Map<String, Object> params = new HashMap<>();
        OpCode op;
        if (isKeyBlock) {
            // B0 — Form TR-31 / X9.143 Key Block
            char formatChar = switch (req.getFormat().toUpperCase()) {
                case "TR31_D" -> 'D';
                case "TR31_B" -> 'B';
                case "X9_143" -> 'X';
                default       -> 'D';
            };
            params.put("kbpkKeyType",  "002");          // KBPK / ZMK family code
            params.put("keyKeyType",   String.format("%03d", req.getKeyType() == null ? 1 : req.getKeyType()));
            params.put("kbpkScheme",   zmkScheme);
            params.put("kbpkUnderLmk", zmkHex);
            params.put("keyScheme",    keyScheme);
            params.put("keyUnderLmk",  keyHex);
            params.put("blockFormat",  String.valueOf(formatChar));
            params.put("usage",        req.getUsage2() == null ? "K0" : req.getUsage2());
            params.put("algo",         req.getAlgo1()  == null ? "T"  : req.getAlgo1());
            params.put("mode",         req.getMode1()  == null ? "E"  : req.getMode1());
            params.put("export",       req.getExport1()== null ? "E"  : req.getExport1());
            op = OpCode.KEY_FORM_BLOCK;
        } else {
            // A8 — legacy ZMK-wrap (returns scheme+hex, no TR-31 envelope)
            params.put("zmkKeyType",  "000");
            params.put("keyKeyType",  String.format("%03d", req.getKeyType() == null ? 1 : req.getKeyType()));
            params.put("zmkScheme",   zmkScheme);
            params.put("zmkUnderLmk", zmkHex);
            params.put("keyScheme",   keyScheme);
            params.put("keyUnderLmk", keyHex);
            params.put("outScheme",   req.getSchemeZmk() == null ? "U" : req.getSchemeZmk());
            op = OpCode.KEY_EXPORT;
        }

        GatewayResponse resp = dispatcher.dispatch(GatewayCommand.builder()
            .op(op)
            .vendorHint(HsmVendor.THALES)
            .params(params)
            .keyId(keyId)
            .userId(userId)
            .build());

        // B0 returns "keyBlock"; A8 returns "keyUnderZmk".
        String keyBlock = (String) resp.getResult().getOrDefault("keyBlock",
                          (String) resp.getResult().getOrDefault("keyUnderZmk",
                          (String) resp.getResult().getOrDefault("raw", "")));
        String kcv = (String) resp.getResult().get("kcv");

        return ExportKeyResponse.builder()
            .keyId(keyId)
            .format(req.getFormat())
            .keyBlock(keyBlock)
            .kcv(kcv != null ? kcv : key.getKcv())
            .status(resp.getStatus())
            .errCode(resp.getErrCode())
            .errText(resp.getErrText())
            .latencyMs(resp.getLatencyMs())
            .build();
    }

    public List<KeySummaryResponse> list(String labelFilter, String keyTypeFilter, Long bankFilter) {
        return keyRepo.findAll().stream()
            .filter(k -> !"INVALID".equals(k.getStatus()))
            .filter(k -> bankFilter == null || (k.getBankRecId() != null && k.getBankRecId().equals(bankFilter)))
            .filter(k -> labelFilter == null || k.getLabel().contains(labelFilter))
            .filter(k -> keyTypeFilter == null || k.getKeyType().equals(keyTypeFilter))
            .map(k -> KeySummaryResponse.builder()
                .keyId(k.getKeyUuid().toString())
                .label(k.getLabel())
                .keyType(k.getKeyType())
                .algo(k.getAlgo())
                .keyLengthBits(k.getKeyLengthBits())
                .status(k.getStatus())
                .kcv(k.getKcv())
                .bankRecId(k.getBankRecId())
                .branchRecId(k.getBranchRecId())
                .createdAt(k.getCreatedAt())
                .build())
            .toList();
    }

    public KeyDetailResponse get(String keyId) {
        HsmKey k = keyRepo.findByKeyUuid(UUID.fromString(keyId))
            .orElseThrow(() -> new IllegalArgumentException("key not found: " + keyId));
        return KeyDetailResponse.builder()
            .keyId(k.getKeyUuid().toString())
            .label(k.getLabel())
            .keyType(k.getKeyType())
            .algo(k.getAlgo())
            .keyLengthBits(k.getKeyLengthBits())
            .usage(k.getUsage())
            .ownerUserId(k.getOwnerUserId())
            .ownerOrg(k.getOwnerOrg())
            .kcv(k.getKcv())
            .vendorOrigin(k.getVendorOrigin())
            .lmkIdx(k.getLmkIdx())
            .status(k.getStatus())
            .version(k.getVersion())
            .tags(k.getTags())
            .createdAt(k.getCreatedAt())
            .activatedAt(k.getActivatedAt())
            .expiresAt(k.getExpiresAt())
            .build();
    }
}
