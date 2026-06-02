package com.isc.sentinel.api.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

/** Decrypt encrypted PIN block (Thales NG/NH). */
@Data
public class PinDecryptRequest {
    /** UUID of ZPK used to encrypt the PIN block. */
    @NotBlank private String keyId;

    /** PIN block (16 hex chars). */
    @NotBlank private String pinBlock;

    /** PIN block format, 2 digits (default "01"). */
    private String pinBlockFormat = "01";

    /** Full PAN (rightmost 12 excl check digit extracted automatically). */
    @NotBlank private String pan;
}
