package com.isc.sentinel.core.audit;

import com.isc.sentinel.persistence.entity.HsmCommandAudit;
import com.isc.sentinel.persistence.repo.HsmCommandAuditRepository;
import com.isc.sentinel.spi.GatewayCommand;
import com.isc.sentinel.spi.GatewayResponse;
import com.isc.sentinel.spi.HsmNodeRef;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.security.MessageDigest;
import java.util.HexFormat;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuditService {

    private final HsmCommandAuditRepository repo;

    public void record(GatewayCommand cmd, GatewayResponse resp, HsmNodeRef node, String traceId) {
        try {
            HsmCommandAudit a = HsmCommandAudit.builder()
                .userId(cmd.getUserId())
                .op(cmd.getOp().name())
                .vendor(resp.getVendor() == null ? null : resp.getVendor().name())
                .hsmNodeId(node == null ? null : node.getId())
                .latencyMs((int) resp.getLatencyMs())
                .status(resp.getStatus())
                .errCode(resp.getErrCode())
                .errText(resp.getErrText())
                .requestHash(hash(cmd.toString()))
                .responseHash(hash(resp.toString()))
                .traceId(traceId)
                .build();
            repo.save(a);
        } catch (Exception e) {
            log.warn("audit persist failed", e);
        }
    }

    private String hash(String s) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(md.digest(s.getBytes())).substring(0, 32);
        } catch (Exception e) {
            return "";
        }
    }
}
