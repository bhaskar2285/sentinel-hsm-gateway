package com.isc.sentinel.api.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class ClearPinEncryptRequest {
    /** Clear PIN digits (4–12). */
    @NotBlank private String clearPin;

    /** UUID of ZPK under LMK. */
    @NotBlank private String zpkKeyId;

    /** PIN block format, 2 digits (default "01"). */
    private String pinBlockFormat = "01";

    /** Full PAN (rightmost 12 excl check digit extracted automatically). */
    @NotBlank private String pan;
}
