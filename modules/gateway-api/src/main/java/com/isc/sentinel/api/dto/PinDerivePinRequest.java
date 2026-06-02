package com.isc.sentinel.api.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class PinDerivePinRequest {
    /** UUID of PVK under LMK. */
    @NotBlank private String pvkKeyId;

    /** IBM PIN offset, 12 decimal chars. */
    @NotBlank private String offset;

    /** Number of PIN digits to derive (default "4"). */
    private String checkLen = "4";

    /** Account number, 12 digits (default zeros). */
    private String accountNo = "000000000000";

    /** Decimalization table, 16 hex chars (default: identity table). */
    private String decimTable = "0123456789012345";

    /** PIN validation data, 12 digits. */
    @NotBlank private String pinValidData;
}
