package com.isc.sentinel.api.dto;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class PinDecryptResponse {
    private String clearPin;
    /** Reference number derived by encrypting the account number under the LMK (NH field). */
    private String referenceNumber;
    private String status;
    private String errCode;
    private String errText;
    private Long   latencyMs;
}
