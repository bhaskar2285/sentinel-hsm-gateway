package com.isc.sentinel.api.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class CvvRequest {
    /** UUID of CVK-A (first half of Card Verification Key) under LMK.
     *  For single-key CVK, use same UUID for cvkaKeyId and cvkbKeyId. */
    @NotBlank private String cvkaKeyId;

    /** UUID of CVK-B (second half). Set same as cvkaKeyId for single-key CVK. */
    @NotBlank private String cvkbKeyId;

    /** Full PAN (13–19 digits). */
    @NotBlank private String pan;

    /** Expiry date in YYMM format, e.g. "2512" for Dec 2025. */
    @NotBlank private String expDate;

    /** 3-digit service code, e.g. "101" for CVV, "000" for CVV2. */
    private String serviceCode = "101";

    /** CVV to verify (only needed for verify endpoint, ignored for generate). */
    private String cvv;
}
