package com.isc.sentinel.api.dto;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class PinFromLmkResponse {
    private String pinBlock;
    private String status;
    private String errCode;
    private String errText;
    private long   latencyMs;
}
