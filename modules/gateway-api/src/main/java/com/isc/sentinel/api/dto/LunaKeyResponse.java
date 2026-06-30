package com.isc.sentinel.api.dto;

import lombok.Data;

/** Response for ZMK form / DEK import: persisted keyId + KCV. */
@Data
public class LunaKeyResponse {
    private String keyId;
    private String kcv;
    private String errCode;
    private String errText;
}
