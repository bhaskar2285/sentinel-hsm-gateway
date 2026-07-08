package com.isc.sentinel.api.dto;

import lombok.Data;

/** Response for ZMK form / DEK import / DEK generate: persisted keyId + KCV. */
@Data
public class LunaKeyResponse {
    private String keyId;
    private String kcv;
    /** For generate: the DEK wrapped under the ZMK (hex) — the exportable key block. */
    private String dekBlob;
    private String errCode;
    private String errText;
}
