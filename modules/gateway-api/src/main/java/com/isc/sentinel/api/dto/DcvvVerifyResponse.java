package com.isc.sentinel.api.dto;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class DcvvVerifyResponse {
    /** true if dCVV matched. */
    private boolean verified;
    private String status;
    private String errCode;
    private String errText;
    private long   latencyMs;
}
