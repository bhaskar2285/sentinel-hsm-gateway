package com.isc.sentinel.api.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class DcvvVerifyRequest {
    /** UUID of MK-DCVV under LMK. */
    @NotBlank private String keyId;

    /** Scheme: "0"=Visa (default), "1"=MC, "2"=AmEx, "3"=Discover. */
    private String schemeId = "0";

    /** Version within scheme: Visa "0"=dCVV. */
    private String version = "0";

    /** Full PAN (13–19 digits). */
    @NotBlank private String pan;

    /** Expiry in YYMM format, e.g. "2512". */
    @NotBlank private String expiry;

    /** 3-digit service code, e.g. "101". */
    private String serviceCode = "101";

    /** Application Transaction Counter — 6 decimal digits, e.g. "000026". */
    @NotBlank private String atc;

    /** Dynamic CVV to verify (3 digits). */
    @NotBlank private String dcvv;
}
