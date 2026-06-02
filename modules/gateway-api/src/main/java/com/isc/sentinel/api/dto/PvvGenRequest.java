package com.isc.sentinel.api.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class PvvGenRequest {
    /** UUID of PVK under LMK. */
    @NotBlank private String pvkKeyId;

    /** Full PAN (rightmost 12 excl check digit extracted automatically). */
    @NotBlank private String pan;

    /** PIN Verification Key Index, 1 digit (default "1"). */
    private String pvki = "1";

    /** PIN under LMK (16 hex chars) — output of JA or prior PIN translate. */
    @NotBlank private String pinUnderLmk;
}
