package com.isc.sentinel.persistence.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.OffsetDateTime;

@Entity
@Table(name = "hsm_command_audit")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class HsmCommandAudit {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private OffsetDateTime ts;

    @Column(name = "user_id", length = 128)
    private String userId;

    @Column(nullable = false, length = 64)
    private String op;

    @Column(name = "vendor_cmd_code", length = 8)
    private String vendorCmdCode;

    @Column(name = "key_id")
    private Long keyId;

    @Column(name = "pool_id")
    private Long poolId;

    @Column(name = "hsm_node_id")
    private Long hsmNodeId;

    @Column(length = 32)
    private String vendor;

    @Column(name = "latency_ms")
    private Integer latencyMs;

    @Column(nullable = false, length = 16)
    private String status;

    @Column(name = "err_code", length = 16)
    private String errCode;

    @Column(name = "err_text", length = 512)
    private String errText;

    @Column(name = "request_hash", length = 64)
    private String requestHash;

    @Column(name = "response_hash", length = 64)
    private String responseHash;

    @Column(name = "trace_id", length = 64)
    private String traceId;

    @PrePersist
    void prePersist() {
        if (ts == null) ts = OffsetDateTime.now();
    }
}
