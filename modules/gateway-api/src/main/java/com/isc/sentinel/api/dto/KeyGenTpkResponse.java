package com.isc.sentinel.api.dto;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class KeyGenTpkResponse {
    private String keyId;
    private String scheme;
    private String keyUnderLmk;
    private String kcv;
    private String status;
    private String errCode;
    private String errText;
    private Long   latencyMs;
}
