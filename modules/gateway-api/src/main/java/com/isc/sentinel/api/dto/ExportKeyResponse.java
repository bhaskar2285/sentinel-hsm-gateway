package com.isc.sentinel.api.dto;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class ExportKeyResponse {
    private String keyId;
    private String format;       // TR31_B / TR31_D / X9_143 / RAW
    private String keyBlock;     // ASCII payload or hex
    private String kcv;
    private String status;
    private String errCode;
    private String errText;
    private long   latencyMs;
}
