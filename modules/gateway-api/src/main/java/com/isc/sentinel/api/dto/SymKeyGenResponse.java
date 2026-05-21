package com.isc.sentinel.api.dto;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class SymKeyGenResponse {
    private String keyId;
    private String kcv;
    /** Present only when request mode="1" (ZMK-wrapped copy of the generated key). */
    private String keyUnderZmk;
    private String status;
    private String errCode;
    private String errText;
    private long   latencyMs;
}
