package com.isc.sentinel.api.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class CscVerifyRequest {
    /** UUID of CSCK under LMK. */
    @NotBlank private String keyId;

    /** Flag: "0"=CSC1, "2"=CSC2, "3"=AEVV. */
    private String flag = "0";

    /** Account number up to 19 digits. */
    @NotBlank private String account;

    /** Expiry in YYMM. */
    @NotBlank private String expiry;

    /** Service code (required for flag=2 or flag=3). */
    private String serviceCode = "000";

    /** 5-digit CSC to verify, or null/omitted to skip. */
    private String csc5;

    /** 4-digit CSC to verify, or null/omitted to skip. */
    private String csc4;

    /** 3-digit CSC (iCSC) to verify — required. */
    @NotBlank private String csc3;
}
