package com.isc.sentinel.api.dto;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class PinTranslateResponse {
    private String translatedPinBlock;
    private String status;
    private String errCode;
    private String errText;
    private long   latencyMs;
}
