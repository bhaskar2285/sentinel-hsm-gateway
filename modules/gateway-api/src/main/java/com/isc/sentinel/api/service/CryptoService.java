package com.isc.sentinel.api.service;

import com.isc.sentinel.api.dto.DecryptRequest;
import com.isc.sentinel.api.dto.DecryptResponse;
import com.isc.sentinel.core.dispatch.CommandDispatcher;
import com.isc.sentinel.persistence.entity.HsmKey;
import com.isc.sentinel.persistence.repo.HsmKeyRepository;
import com.isc.sentinel.spi.GatewayCommand;
import com.isc.sentinel.spi.GatewayResponse;
import com.isc.sentinel.spi.HsmVendor;
import com.isc.sentinel.spi.OpCode;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class CryptoService {

    private final CommandDispatcher dispatcher;
    private final HsmKeyRepository keyRepo;

    public DecryptResponse decrypt(DecryptRequest req, String userId) {
        HsmKey k = keyRepo.findByKeyUuid(UUID.fromString(req.getKeyId()))
            .orElseThrow(() -> new IllegalArgumentException("key not found: " + req.getKeyId()));

        Map<String, Object> params = new HashMap<>();
        params.put("mode", req.getMode());
        params.put("inputFormat", req.getInputFormat());
        params.put("outputFormat", req.getOutputFormat());
        params.put("keyType", familyCodeForKeyType(k.getKeyType()));
        String blob = k.getEncryptedBlob() == null ? "" : new String(k.getEncryptedBlob());
        params.put("keyHex", blob);
        if (req.getIv() != null && !req.getIv().isEmpty()) {
            String sch = blob.isEmpty() ? "U" : blob.substring(0, 1);
            params.put("iv", sizeIv(req.getIv(), sch));
        }
        params.put("messageHex", req.getCiphertextHex());

        GatewayResponse resp = dispatcher.dispatch(GatewayCommand.builder()
            .op(OpCode.DATA_DECRYPT)
            .vendorHint(HsmVendor.THALES)
            .params(params)
            .keyId(req.getKeyId())
            .userId(userId)
            .build());

        return DecryptResponse.builder()
            .plaintextHex((String) resp.getResult().get("plaintext"))
            .status(resp.getStatus())
            .errCode(resp.getErrCode())
            .errText(resp.getErrText())
            .latencyMs(resp.getLatencyMs())
            .build();
    }

    private static String sizeIv(String iv, String scheme) {
        int t = (scheme != null && !scheme.isEmpty()
              && (scheme.charAt(0)=='R' || scheme.charAt(0)=='S' || scheme.charAt(0)=='H')) ? 32 : 16;
        if (iv.length() == t) return iv;
        if (iv.length() > t)  return iv.substring(0, t);
        return iv + "0".repeat(t - iv.length());
    }

    private static String familyCodeForKeyType(String name) {
        if (name == null) return "00A";
        return switch (name) {
            case "ZMK"  -> "000";
            case "ZPK"  -> "001";
            case "KBPK" -> "002";
            case "TMK"  -> "008";
            case "DATA" -> "00A";
            default     -> "00A";
        };
    }
}
