package com.isc.sentinel.api.dto;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class CscCalcResponse {
    /** 5-digit CSC value. */
    private String csc5;
    /** 4-digit CSC value. */
    private String csc4;
    /** 3-digit CSC (iCSC) value. */
    private String csc3;
    private String status;
    private String errCode;
    private String errText;
    private long   latencyMs;
}
