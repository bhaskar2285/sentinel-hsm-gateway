package com.isc.sentinel.api.dto;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class PinDecryptResponse {
    private String clearPin;
    private String status;
    private String errCode;
    private String errText;
    private Long   latencyMs;
}
