package com.isc.sentinel.api.service;

import com.isc.sentinel.api.dto.LunaDataRequest;
import com.isc.sentinel.api.dto.LunaDataResponse;
import com.isc.sentinel.api.dto.LunaDekGenRequest;
import com.isc.sentinel.api.dto.LunaDekImportRequest;
import com.isc.sentinel.api.dto.LunaDekWrapTestRequest;
import com.isc.sentinel.api.dto.LunaDekWrapTestResponse;
import com.isc.sentinel.api.dto.LunaExportRequest;
import com.isc.sentinel.api.dto.LunaExportResponse;
import com.isc.sentinel.api.dto.LunaKbpkRequest;
import com.isc.sentinel.api.dto.LunaKcvRequest;
import com.isc.sentinel.api.dto.LunaKeyResponse;
import com.isc.sentinel.api.dto.LunaTr31BlockSummary;
import com.isc.sentinel.api.dto.LunaTr31Response;
import com.isc.sentinel.api.dto.LunaTr31UnwrapRequest;
import com.isc.sentinel.api.dto.LunaTr31WrapRequest;
import com.isc.sentinel.api.dto.LunaZmkFormRequest;
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

/**
 * Luna (PKCS#11) custodian ceremony + data crypto. Fully separate from the Thales payShield path.
 *
 * Model: the ZMK is a token object in the Luna partition (DB row stores only its label); the DEK is
 * stored as a ciphertext blob (DEK wrapped under the ZMK) in {@code encryptedBlob} and unwrapped
 * inside the HSM on every encrypt/decrypt. The clear DEK never reaches host memory.
 */
@Service
@RequiredArgsConstructor
public class LunaCryptoService {

    private final CommandDispatcher dispatcher;
    private final HsmKeyRepository keyRepo;

    /** Form a ZMK from clear components and persist it (label -> partition object). */
    public LunaKeyResponse formZmk(LunaZmkFormRequest req, String userId, Long bankRecId) {
        Map<String, Object> p = new HashMap<>();
        p.put("components", req.getComponents());
        p.put("algorithm", req.getAlgorithm());
        p.put("label", req.getLabel());
        GatewayResponse r = dispatcher.dispatch(GatewayCommand.builder()
            .op(OpCode.KEY_FORM_COMPONENTS).vendorHint(HsmVendor.LUNA).params(p).userId(userId).build());

        LunaKeyResponse out = new LunaKeyResponse();
        out.setErrCode(r.getErrCode());
        out.setErrText(r.getErrText());
        out.setKcv((String) r.getResult().get("kcv"));
        if ("OK".equals(r.getStatus())) {
            int bits = req.getComponents().get(0).trim().length() / 2 * 8;
            HsmKey saved = keyRepo.save(HsmKey.builder()
                .keyUuid(UUID.randomUUID())
                .label(req.getLabel())
                .keyType("ZMK")
                .algo(req.getAlgorithm())
                .keyLengthBits(bits)
                .usage("WRAP,UNWRAP")
                .ownerUserId(userId)
                .bankRecId(bankRecId)
                .kcv(out.getKcv())
                .vendorOrigin("luna")
                .status("ACTIVE")
                .version(1)
                .build());
            out.setKeyId(saved.getKeyUuid().toString());
        }
        return out;
    }

    /** Validate a DEK delivered under the ZMK (unwrap inside HSM) and persist its blob. */
    public LunaKeyResponse importDek(LunaDekImportRequest req, String userId, Long bankRecId) {
        HsmKey zmk = keyRepo.findByKeyUuid(UUID.fromString(req.getZmkKeyId()))
            .orElseThrow(() -> new IllegalArgumentException("ZMK not found: " + req.getZmkKeyId()));

        Map<String, Object> p = new HashMap<>();
        p.put("zmkLabel", zmk.getLabel());
        p.put("dekBlob", req.getDekBlob());
        p.put("wrapMech", req.getWrapMech());
        p.put("dekAlgorithm", req.getAlgorithm());
        GatewayResponse r = dispatcher.dispatch(GatewayCommand.builder()
            .op(OpCode.KEY_IMPORT_ZMK).vendorHint(HsmVendor.LUNA).params(p).userId(userId).build());

        LunaKeyResponse out = new LunaKeyResponse();
        out.setErrCode(r.getErrCode());
        out.setErrText(r.getErrText());
        out.setKcv((String) r.getResult().get("kcv"));
        if ("OK".equals(r.getStatus())) {
            HsmKey saved = keyRepo.save(HsmKey.builder()
                .keyUuid(UUID.randomUUID())
                .label(req.getLabel())
                .keyType("DATA")
                .algo(req.getAlgorithm())
                .keyLengthBits(req.getDekBlob().trim().length() / 2 * 8)
                .usage("ENC,DEC")
                .ownerUserId(userId)
                .bankRecId(bankRecId)
                .kcv(out.getKcv())
                .vendorOrigin("luna")
                .wrapKeyId(zmk.getId())
                .encryptedBlob(req.getDekBlob().getBytes(StandardCharsets.US_ASCII))
                .status("ACTIVE")
                .version(1)
                .build());
            out.setKeyId(saved.getKeyUuid().toString());
        }
        return out;
    }

    /** Generate a fresh DEK in-HSM (wrapped under the ZMK) and persist its blob. */
    public LunaKeyResponse generateDek(LunaDekGenRequest req, String userId, Long bankRecId) {
        HsmKey zmk = keyRepo.findByKeyUuid(UUID.fromString(req.getZmkKeyId()))
            .orElseThrow(() -> new IllegalArgumentException("ZMK not found: " + req.getZmkKeyId()));

        Map<String, Object> p = new HashMap<>();
        p.put("zmkLabel", zmk.getLabel());
        p.put("algorithm", req.getAlgorithm());
        if (req.getKeyBits() != null) p.put("keyBits", req.getKeyBits());
        GatewayResponse r = dispatcher.dispatch(GatewayCommand.builder()
            .op(OpCode.KEY_GEN_DEK).vendorHint(HsmVendor.LUNA).params(p).userId(userId).build());

        LunaKeyResponse out = new LunaKeyResponse();
        out.setErrCode(r.getErrCode());
        out.setErrText(r.getErrText());
        out.setKcv((String) r.getResult().get("kcv"));
        if ("OK".equals(r.getStatus())) {
            String dekBlob = (String) r.getResult().get("dekBlob");
            out.setDekBlob(dekBlob); // surface the wrapped block so it can be exported / re-imported
            HsmKey saved = keyRepo.save(HsmKey.builder()
                .keyUuid(UUID.randomUUID())
                .label(req.getLabel())
                .keyType("DATA")
                .algo(req.getAlgorithm())
                .keyLengthBits(dekBlob.length() / 2 * 8)
                .usage("ENC,DEC")
                .ownerUserId(userId)
                .bankRecId(bankRecId)
                .kcv(out.getKcv())
                .vendorOrigin("luna")
                .wrapKeyId(zmk.getId())
                .encryptedBlob(dekBlob.getBytes(StandardCharsets.US_ASCII))
                .status("ACTIVE")
                .version(1)
                .build());
            out.setKeyId(saved.getKeyUuid().toString());
        }
        return out;
    }

    /** Export a stored DEK as its ZMK-wrapped key block (hex) — the blob you can re-import or deliver. */
    public LunaExportResponse exportDek(String keyId) {
        HsmKey dek = keyRepo.findByKeyUuid(UUID.fromString(keyId))
            .orElseThrow(() -> new IllegalArgumentException("DEK not found: " + keyId));
        if (dek.getEncryptedBlob() == null || dek.getWrapKeyId() == null)
            throw new IllegalArgumentException("key " + keyId + " is not a Luna ZMK-wrapped DEK");

        LunaExportResponse out = new LunaExportResponse();
        out.setKeyId(keyId);
        out.setLabel(dek.getLabel());
        out.setAlgorithm(dek.getAlgo());
        out.setKcv(dek.getKcv());
        out.setDekBlob(new String(dek.getEncryptedBlob(), StandardCharsets.US_ASCII));
        keyRepo.findById(dek.getWrapKeyId()).ifPresent(zmk -> {
            out.setZmkKeyId(zmk.getKeyUuid().toString());
            out.setZmkLabel(zmk.getLabel());
        });
        out.setErrCode("00");
        return out;
    }

    /** KCV of a clear key value (advisory per-component check during the ZMK ceremony). */
    public LunaKeyResponse kcv(LunaKcvRequest req, String userId) {
        Map<String, Object> p = new HashMap<>();
        p.put("valueHex", req.getValueHex());
        p.put("algorithm", req.getAlgorithm());
        GatewayResponse r = dispatcher.dispatch(GatewayCommand.builder()
            .op(OpCode.KEY_CHECK_VALUE).vendorHint(HsmVendor.LUNA).params(p).userId(userId).build());

        LunaKeyResponse out = new LunaKeyResponse();
        out.setErrCode(r.getErrCode());
        out.setErrText(r.getErrText());
        out.setKcv((String) r.getResult().get("kcv"));
        return out;
    }

    public LunaDataResponse encrypt(LunaDataRequest req, String userId) {
        return cipher(req, userId, OpCode.DATA_ENCRYPT);
    }

    public LunaDataResponse decrypt(LunaDataRequest req, String userId) {
        return cipher(req, userId, OpCode.DATA_DECRYPT);
    }

    private LunaDataResponse cipher(LunaDataRequest req, String userId, OpCode op) {
        HsmKey dek = keyRepo.findByKeyUuid(UUID.fromString(req.getKeyId()))
            .orElseThrow(() -> new IllegalArgumentException("DEK not found: " + req.getKeyId()));

        Map<String, Object> p = new HashMap<>();
        if ("TR31_BLOCK".equals(dek.getKeyType())) {
            // TR-31-wrapped DEK: recover the clear key under its KBPK, then cipher with it.
            HsmKey kbpk = keyRepo.findById(dek.getWrapKeyId())
                .orElseThrow(() -> new IllegalArgumentException("KBPK not found for block " + req.getKeyId()));
            GatewayResponse uw = dispatcher.dispatch(GatewayCommand.builder()
                .op(OpCode.TR31_UNWRAP).vendorHint(HsmVendor.LUNA).userId(userId)
                .params(Map.of(
                    "kbpkHex", new String(kbpk.getEncryptedBlob(), StandardCharsets.US_ASCII),
                    "tr31Block", new String(dek.getEncryptedBlob(), StandardCharsets.US_ASCII)))
                .build());
            if (!"OK".equals(uw.getStatus())) {
                LunaDataResponse e = new LunaDataResponse();
                e.setErrCode(uw.getErrCode()); e.setErrText(uw.getErrText());
                return e;
            }
            p.put("clearKeyHex", uw.getResult().get("workingKeyHex"));
            p.put("algorithm", dek.getAlgo() == null ? "AES" : dek.getAlgo());
        } else {
            // ZMK-wrapped DEK: unwrap under the ZMK inside the HSM per op.
            if (dek.getEncryptedBlob() == null || dek.getWrapKeyId() == null)
                throw new IllegalArgumentException("key " + req.getKeyId() + " is not a Luna wrapped DEK");
            HsmKey zmk = keyRepo.findById(dek.getWrapKeyId())
                .orElseThrow(() -> new IllegalArgumentException("wrapping ZMK not found for DEK " + req.getKeyId()));
            p.put("zmkLabel", zmk.getLabel());
            p.put("dekBlob", new String(dek.getEncryptedBlob(), StandardCharsets.US_ASCII));
            p.put("dekAlgorithm", dek.getAlgo());
        }
        p.put("transformation", req.getTransformation());
        p.put("data", req.getData());
        if (req.getIv() != null && !req.getIv().isBlank()) p.put("iv", req.getIv());

        GatewayResponse r = dispatcher.dispatch(GatewayCommand.builder()
            .op(op).vendorHint(HsmVendor.LUNA).keyId(req.getKeyId()).params(p).userId(userId).build());

        LunaDataResponse out = new LunaDataResponse();
        out.setErrCode(r.getErrCode());
        out.setErrText(r.getErrText());
        out.setCiphertext((String) r.getResult().get("ciphertext"));
        out.setPlaintext((String) r.getResult().get("plaintext"));
        out.setIv((String) r.getResult().get("iv"));
        return out;
    }

    // ---- TR-31 / KBPK -------------------------------------------------------

    /**
     * Generate a KBPK and persist it. The clear KBPK is stored in {@code encryptedBlob}
     * (software TR-31 codec needs the clear bytes; same trust model as the clear-component
     * ZMK ceremony). version D -> AES, B -> 3DES.
     */
    public LunaKeyResponse generateKbpk(LunaKbpkRequest req, String userId, Long bankRecId) {
        Map<String, Object> p = new HashMap<>();
        p.put("version", req.getVersion());
        p.put("keyBits", req.getKeyBits());
        GatewayResponse r = dispatcher.dispatch(GatewayCommand.builder()
            .op(OpCode.KBPK_GEN).vendorHint(HsmVendor.LUNA).params(p).userId(userId).build());

        LunaKeyResponse out = new LunaKeyResponse();
        out.setErrCode(r.getErrCode());
        out.setErrText(r.getErrText());
        out.setKcv((String) r.getResult().get("kcv"));
        if ("OK".equals(r.getStatus())) {
            String kbpkHex = (String) r.getResult().get("kbpkHex");
            HsmKey saved = keyRepo.save(HsmKey.builder()
                .keyUuid(UUID.randomUUID())
                .label(req.getLabel())
                .keyType("KBPK")
                .algo((String) r.getResult().get("algorithm"))
                .keyLengthBits((Integer) req.getKeyBits())
                .usage("TR31_WRAP,TR31_UNWRAP")
                .ownerUserId(userId)
                .bankRecId(bankRecId)
                .kcv(out.getKcv())
                .vendorOrigin("luna")
                .encryptedBlob(kbpkHex.getBytes(StandardCharsets.US_ASCII))
                .status("ACTIVE")
                .version(1)
                .build());
            out.setKeyId(saved.getKeyUuid().toString());
        }
        return out;
    }

    public LunaTr31Response tr31Wrap(LunaTr31WrapRequest req, String userId, Long bankRecId) {
        HsmKey kbpk = loadKbpk(req.getKbpkKeyId());
        Map<String, Object> p = new HashMap<>();
        p.put("version", "AES".equals(kbpk.getAlgo()) ? "D" : "B");
        p.put("kbpkHex", new String(kbpk.getEncryptedBlob(), StandardCharsets.US_ASCII));
        p.put("workingKeyHex", req.getWorkingKeyHex());
        p.put("keyAlgorithm", req.getKeyAlgorithm());
        p.put("keyUsage", req.getKeyUsage());
        p.put("modeOfUse", req.getModeOfUse());
        p.put("exportability", req.getExportability());
        GatewayResponse r = dispatcher.dispatch(GatewayCommand.builder()
            .op(OpCode.TR31_WRAP).vendorHint(HsmVendor.LUNA).params(p).userId(userId).build());

        LunaTr31Response out = new LunaTr31Response();
        out.setErrCode(r.getErrCode());
        out.setErrText(r.getErrText());
        out.setTr31Block((String) r.getResult().get("tr31Block"));
        out.setHeader((String) r.getResult().get("header"));
        out.setVersion((String) r.getResult().get("version"));
        // Always persist the produced block to the vault (it is the system of record, not the UI).
        if ("OK".equals(r.getStatus())) {
            String label = (req.getLabel() != null && !req.getLabel().isBlank())
                ? req.getLabel()
                : "tr31-" + kbpk.getLabel() + "-" + System.currentTimeMillis();
            HsmKey saved = keyRepo.save(HsmKey.builder()
                .keyUuid(UUID.randomUUID())
                .label(label)
                .keyType("TR31_BLOCK")
                .algo((String) r.getResult().get("keyAlgorithm"))   // wrapped key's algorithm
                .keyLengthBits((Integer) r.getResult().get("keyBits"))
                .usage(req.getKeyUsage())
                .ownerUserId(userId)
                .bankRecId(bankRecId)
                .vendorOrigin("luna")
                .wrapKeyId(kbpk.getId())
                .encryptedBlob(out.getTr31Block().getBytes(StandardCharsets.US_ASCII))
                .status("ACTIVE")
                .version(1)
                .build());
            out.setKeyId(saved.getKeyUuid().toString());
        }
        return out;
    }

    /** List stored TR-31 key blocks (for the unwrap / crypto dropdowns). */
    public List<LunaTr31BlockSummary> listTr31Blocks() {
        return keyRepo.findByKeyTypeAndVendorOriginAndStatus("TR31_BLOCK", "luna", "ACTIVE").stream()
            .map(k -> {
                LunaTr31BlockSummary s = new LunaTr31BlockSummary();
                s.setKeyId(k.getKeyUuid().toString());
                s.setLabel(k.getLabel());
                String block = new String(k.getEncryptedBlob(), StandardCharsets.US_ASCII);
                s.setTr31Block(block);
                s.setHeader(block.length() >= 16 ? block.substring(0, 16) : block);
                s.setVersion(block.isEmpty() ? null : String.valueOf(block.charAt(0)));
                s.setKeyAlgorithm(k.getAlgo());
                s.setKeyBits(k.getKeyLengthBits());
                if (k.getWrapKeyId() != null) {
                    keyRepo.findById(k.getWrapKeyId()).ifPresent(kbpk -> {
                        s.setKbpkKeyId(kbpk.getKeyUuid().toString());
                        s.setKbpkLabel(kbpk.getLabel());
                    });
                }
                s.setCreatedAt(k.getCreatedAt() == null ? null : k.getCreatedAt().toString());
                return s;
            })
            .toList();
    }

    /** Compute the KCV of a clear key value (e.g. a ZMK component) — software, no partition. */
    public LunaKeyResponse computeKcv(LunaKcvRequest req, String userId) {
        GatewayResponse r = dispatcher.dispatch(GatewayCommand.builder()
            .op(OpCode.KEY_CHECK_VALUE).vendorHint(HsmVendor.LUNA).userId(userId)
            .params(Map.of("valueHex", req.getValueHex(), "algorithm", req.getAlgorithm())).build());
        LunaKeyResponse out = new LunaKeyResponse();
        out.setErrCode(r.getErrCode());
        out.setErrText(r.getErrText());
        out.setKcv((String) r.getResult().get("kcv"));
        return out;
    }

    /** Luna-native export: TR-31-wrap a stored Luna key under a transport KBPK (replaces A8/A9). */
    public LunaTr31Response exportLunaKey(LunaExportRequest req, String userId, Long bankRecId) {
        HsmKey key = keyRepo.findByKeyUuid(UUID.fromString(req.getKeyId()))
            .orElseThrow(() -> new IllegalArgumentException("key not found: " + req.getKeyId()));
        // Only keys whose stored blob IS the clear key can be software-TR-31-exported.
        // KBPK -> clear hex (exportable). ZMK -> partition token object, no clear in DB.
        // DEK  -> blob is the ZMK-wrapped form, not the clear key. Both unsupported here.
        if (!"luna".equals(key.getVendorOrigin()) || !"KBPK".equals(key.getKeyType())
                || key.getEncryptedBlob() == null) {
            LunaTr31Response err = new LunaTr31Response();
            err.setErrCode("UNSUPPORTED");
            err.setErrText("Only a Luna KBPK can be TR-31-exported. '" + key.getKeyType()
                + "' has no exportable clear (a ZMK is a partition token object; a DEK is stored "
                + "ZMK-wrapped) — exporting it needs the in-HSM key-block mechanism.");
            return err;
        }
        // The exported key's clear is the stored KBPK blob.
        String clearHex = new String(key.getEncryptedBlob(), StandardCharsets.US_ASCII);
        LunaTr31WrapRequest wrap = new LunaTr31WrapRequest();
        wrap.setKbpkKeyId(req.getTransportKbpkId());
        wrap.setWorkingKeyHex(clearHex);
        wrap.setKeyAlgorithm("AES".equals(key.getAlgo()) ? "AES" : "DESede");
        wrap.setKeyUsage(req.getKeyUsage());
        wrap.setLabel("export-" + key.getLabel() + "-" + System.currentTimeMillis());
        return tr31Wrap(wrap, userId, bankRecId);
    }

    public LunaTr31Response tr31Unwrap(LunaTr31UnwrapRequest req, String userId) {
        HsmKey kbpk = loadKbpk(req.getKbpkKeyId());
        Map<String, Object> p = new HashMap<>();
        p.put("kbpkHex", new String(kbpk.getEncryptedBlob(), StandardCharsets.US_ASCII));
        p.put("tr31Block", req.getTr31Block());
        GatewayResponse r = dispatcher.dispatch(GatewayCommand.builder()
            .op(OpCode.TR31_UNWRAP).vendorHint(HsmVendor.LUNA).params(p).userId(userId).build());

        LunaTr31Response out = new LunaTr31Response();
        out.setErrCode(r.getErrCode());
        out.setErrText(r.getErrText());
        out.setWorkingKeyHex((String) r.getResult().get("workingKeyHex"));
        out.setHeader((String) r.getResult().get("header"));
        out.setVersion((String) r.getResult().get("version"));
        return out;
    }

    /** TEST helper — wrap a clear DEK under a clear ZMK to produce a dekBlob for /luna/dek/import. */
    public LunaDekWrapTestResponse dekWrapTest(LunaDekWrapTestRequest req, String userId) {
        Map<String, Object> p = new HashMap<>();
        if (req.getComponents() != null && !req.getComponents().isEmpty())
            p.put("components", req.getComponents());
        if (req.getZmkHex() != null && !req.getZmkHex().isBlank())
            p.put("zmkHex", req.getZmkHex());
        p.put("dekHex", req.getDekHex());
        p.put("algorithm", req.getAlgorithm());
        GatewayResponse r = dispatcher.dispatch(GatewayCommand.builder()
            .op(OpCode.DEK_WRAP_TEST).vendorHint(HsmVendor.LUNA).params(p).userId(userId).build());

        LunaDekWrapTestResponse out = new LunaDekWrapTestResponse();
        out.setErrCode(r.getErrCode());
        out.setErrText(r.getErrText());
        out.setDekBlob((String) r.getResult().get("dekBlob"));
        out.setZmkKcv((String) r.getResult().get("zmkKcv"));
        out.setDekKcv((String) r.getResult().get("dekKcv"));
        out.setAlgorithm((String) r.getResult().get("algorithm"));
        return out;
    }

    private HsmKey loadKbpk(String keyId) {
        HsmKey k = keyRepo.findByKeyUuid(UUID.fromString(keyId))
            .orElseThrow(() -> new IllegalArgumentException("KBPK not found: " + keyId));
        if (!"KBPK".equals(k.getKeyType()) || k.getEncryptedBlob() == null)
            throw new IllegalArgumentException("key " + keyId + " is not a KBPK");
        return k;
    }
}
