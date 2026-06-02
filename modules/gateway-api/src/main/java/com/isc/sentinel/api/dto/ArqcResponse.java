package com.isc.sentinel.api.dto;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class ArqcResponse {
    /** Generated ARPC, 16 hex chars (8 bytes) — send back to card. */
    private String arpc;
    private String status;
    private String errCode;
    private String errText;
    private long   latencyMs;
}
