package com.isc.sentinel.api.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class PinToLmkRequest {
    /** UUID of TPK or ZPK under LMK. */
    @NotBlank private String keyId;

    /** "TPK" (uses JC) or "ZPK" (uses JE) — default "TPK". */
    private String inputKeyScheme = "TPK";

    /** Max PIN length, 2 digits (default "12"). */
    private String maxPinLen = "12";

    /** PIN block, 16 hex chars. */
    @NotBlank private String pinBlock;

    /** PIN block format, 2 digits (default "01"). */
    private String pinBlockFormat = "01";

    /** Full PAN (rightmost 12 excl check digit extracted automatically). */
    @NotBlank private String pan;
}
