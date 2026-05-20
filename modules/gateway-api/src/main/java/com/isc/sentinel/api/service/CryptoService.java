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
        params.put("keyType", "00A"); // TODO map from k.getKeyType()
        params.put("keyHex", k.getEncryptedBlob() == null ? "" : new String(k.getEncryptedBlob()));
        if (req.getIv() != null) params.put("iv", req.getIv());
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
}
