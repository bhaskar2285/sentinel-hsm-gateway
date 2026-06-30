package com.isc.sentinel.api.service;

import com.isc.sentinel.api.dto.LunaDataRequest;
import com.isc.sentinel.api.dto.LunaDataResponse;
import com.isc.sentinel.api.dto.LunaDekImportRequest;
import com.isc.sentinel.api.dto.LunaKeyResponse;
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

    public LunaDataResponse encrypt(LunaDataRequest req, String userId) {
        return cipher(req, userId, OpCode.DATA_ENCRYPT);
    }

    public LunaDataResponse decrypt(LunaDataRequest req, String userId) {
        return cipher(req, userId, OpCode.DATA_DECRYPT);
    }

    private LunaDataResponse cipher(LunaDataRequest req, String userId, OpCode op) {
        HsmKey dek = keyRepo.findByKeyUuid(UUID.fromString(req.getKeyId()))
            .orElseThrow(() -> new IllegalArgumentException("DEK not found: " + req.getKeyId()));
        if (dek.getEncryptedBlob() == null || dek.getWrapKeyId() == null)
            throw new IllegalArgumentException("key " + req.getKeyId() + " is not a Luna ZMK-wrapped DEK");
        HsmKey zmk = keyRepo.findById(dek.getWrapKeyId())
            .orElseThrow(() -> new IllegalArgumentException("wrapping ZMK not found for DEK " + req.getKeyId()));

        Map<String, Object> p = new HashMap<>();
        p.put("zmkLabel", zmk.getLabel());
        p.put("dekBlob", new String(dek.getEncryptedBlob(), StandardCharsets.US_ASCII));
        p.put("dekAlgorithm", dek.getAlgo());
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
}
