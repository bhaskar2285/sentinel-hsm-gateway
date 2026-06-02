package com.isc.sentinel.api.dto;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class HmacGenResponse {
    /** Computed HMAC, hex-encoded. */
    private String hmac;
    private String status;
    private String errCode;
    private String errText;
    private long   latencyMs;
}
