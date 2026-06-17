package com.isc.sentinel.api.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

/** Decrypt an LMK-encrypted PIN (Thales NG/NH). No ZPK / PIN block involved. */
@Data
public class PinDecryptRequest {
    /** Full PAN — rightmost 12 digits (excl. check digit) form the account number. */
    @NotBlank private String pan;

    /** PIN encrypted under the LMK (the BA/JA output). */
    @NotBlank private String pinUnderLmk;
}
