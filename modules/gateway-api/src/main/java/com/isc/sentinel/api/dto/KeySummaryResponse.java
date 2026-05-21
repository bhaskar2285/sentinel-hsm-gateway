package com.isc.sentinel.api.dto;

import lombok.Builder;
import lombok.Data;

import java.time.OffsetDateTime;

@Data
@Builder
public class KeySummaryResponse {
    private String keyId;
    private String label;
    private String keyType;
    private String algo;
    private Integer keyLengthBits;
    private String status;
    private String kcv;
    private Long   bankRecId;
    private Long   branchRecId;
    private OffsetDateTime createdAt;
}
