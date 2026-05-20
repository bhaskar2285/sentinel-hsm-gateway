package com.isc.sentinel.api.dto;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class RsaKeyGenResponse {
    private String keyId;
    private String publicKey;          // hex/ASN.1
    private String kcv;
    private String status;
    private String errCode;
    private String errText;
    private long   latencyMs;
}
