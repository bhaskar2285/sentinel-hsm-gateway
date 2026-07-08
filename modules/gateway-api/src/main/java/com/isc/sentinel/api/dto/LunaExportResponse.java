package com.isc.sentinel.api.dto;

import lombok.Data;

/** Export a stored Luna DEK as its ZMK-wrapped key block (for delivery / re-import). */
@Data
public class LunaExportResponse {
    private String keyId;
    private String label;
    private String algorithm;
    private String kcv;
    /** The DEK wrapped under its ZMK (hex) — safe to transport; the clear key stays in the HSM. */
    private String dekBlob;
    private String zmkKeyId;
    private String zmkLabel;
    private String errCode;
    private String errText;
}
