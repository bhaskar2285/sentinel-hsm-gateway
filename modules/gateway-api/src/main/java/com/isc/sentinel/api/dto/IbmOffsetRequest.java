package com.isc.sentinel.api.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class IbmOffsetRequest {
    /** UUID of PVK under LMK. */
    @NotBlank private String pvkKeyId;

    /** PIN under LMK (16 hex chars). */
    @NotBlank private String pinUnderLmk;

    /** Full PAN (rightmost 12 excl check digit extracted automatically). */
    @NotBlank private String pan;

    /** Decimalization table, 16 hex chars (default: identity table). */
    private String decimTable = "0123456789012345";

    /** PIN validation data, 12 digits (defaults to PAN12). */
    private String pinValidData;

    /** Check length 1–12 (default "4"). */
    private String checkLen = "4";
}
