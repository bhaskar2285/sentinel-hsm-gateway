package com.isc.sentinel.api.dto;

import lombok.Builder;
import lombok.Data;

import java.time.OffsetDateTime;

@Data
@Builder
public class KeyDetailResponse {
    private String keyId;
    private String label;
    private String keyType;
    private String algo;
    private Integer keyLengthBits;
    private String usage;
    private String ownerUserId;
    private String ownerOrg;
    private String kcv;
    private String vendorOrigin;
    private Short lmkIdx;
    private String status;
    private Integer version;
    private String tags;
    private OffsetDateTime createdAt;
    private OffsetDateTime activatedAt;
    private OffsetDateTime expiresAt;
}
