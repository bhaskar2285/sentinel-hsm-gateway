package com.isc.sentinel.api.dto;

import lombok.Data;

/** TEST helper output — the dekBlob to paste into /luna/dek/import, plus KCVs to verify. */
@Data
public class LunaDekWrapTestResponse {
    private String dekBlob;   // DEK wrapped under the ZMK (hex)
    private String zmkKcv;    // KCV of the formed ZMK (match against /luna/zmk/form)
    private String dekKcv;    // KCV of the DEK (match against /luna/dek/import)
    private String algorithm;
    private String errCode;
    private String errText;
}
