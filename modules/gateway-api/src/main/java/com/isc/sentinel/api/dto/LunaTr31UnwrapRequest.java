package com.isc.sentinel.api.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

/** Unwrap (and authenticate) a TR-31 key block under a stored KBPK. */
@Data
public class LunaTr31UnwrapRequest {
    /** keyUuid of the KBPK that protects this block. */
    @NotBlank
    private String kbpkKeyId;

    /** The TR-31 key block (ASCII: header + hex ciphertext + hex MAC). */
    @NotBlank
    private String tr31Block;
}
