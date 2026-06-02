package com.isc.sentinel.api.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class CscCalcRequest {
    /** UUID of CSCK (Card Security Code Key) under LMK. */
    @NotBlank private String keyId;

    /** Flag: "0"=CSC1, "2"=CSC2, "3"=AEVV. */
    private String flag = "0";

    /** Account number up to 19 digits. */
    @NotBlank private String account;

    /** Expiry in YYMM, e.g. "2512". For AEVV: unpredictable number (4N). */
    @NotBlank private String expiry;

    /** Service code (required for flag=2 or flag=3). */
    private String serviceCode = "000";
}
