package com.isc.sentinel.api.dto;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class CvvResponse {
    /** Generated CVV (3 digits) — present only on generate. */
    private String cvv;
    private String status;
    private String errCode;
    private String errText;
    private long   latencyMs;
}
