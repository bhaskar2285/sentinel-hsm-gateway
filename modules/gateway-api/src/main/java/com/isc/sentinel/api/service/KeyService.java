package com.isc.sentinel.api.service;

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

    public RsaKeyGenResponse generateRsa(RsaKeyGenRequest req, String userId) {
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
        if ("OK".equals(resp.getStatus())) {
            publicKey = (String) resp.getResult().get("publicKey");
            String privUnderLmk = (String) resp.getResult().get("privateKeyUnderLmk");

            HsmKey saved = keyRepo.save(HsmKey.builder()
                .keyUuid(UUID.randomUUID())
                .label(req.getLabel())
                .keyType("RSA")
                .algo("RSA")
                .keyLengthBits(req.getModulusBits())
                .usage(req.getUsage())
                .ownerUserId(userId)
                .ownerOrg(req.getOwnerOrg())
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
            .status(resp.getStatus())
            .errCode(resp.getErrCode())
            .errText(resp.getErrText())
            .latencyMs(resp.getLatencyMs())
            .build();
    }

    public KeyImportResponse importRsaWrapped(ImportRsaWrappedRequest req, String userId) {
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

    public ExportKeyResponse exportKey(String keyId, ExportKeyRequest req, String userId) {
        HsmKey key = keyRepo.findByKeyUuid(UUID.fromString(keyId))
            .orElseThrow(() -> new IllegalArgumentException("key not found: " + keyId));

        String keyBlob = new String(key.getEncryptedBlob() == null ? new byte[0] : key.getEncryptedBlob(), StandardCharsets.US_ASCII);

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
                .errText("Source key has no LMK-encrypted material (encrypted_blob empty)")
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

    public List<KeySummaryResponse> list(String labelFilter, String keyTypeFilter) {
        return keyRepo.findAll().stream()
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
