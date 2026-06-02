package com.isc.sentinel.api.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class PinVerifyVisaRequest {
    /** UUID of TPK (or ZPK for interchange) under LMK. */
    @NotBlank private String tpkKeyId;

    /** UUID of PVK under LMK. */
    @NotBlank private String pvkKeyId;

    /** Max PIN length, 2 digits (default "12"). */
    private String maxPinLen = "12";

    /** PIN block from terminal, 16 hex chars. */
    @NotBlank private String pinBlock;

    /** PIN block format, 2 digits (default "01"). */
    private String pinBlockFormat = "01";

    /** Full PAN (rightmost 12 excl check digit extracted automatically). */
    @NotBlank private String pan;

    /** PIN Verification Key Index, 1 digit (default "1"). */
    private String pvki = "1";

    /** VISA PVV, 4 decimal digits. */
    @NotBlank private String pvv;
}
