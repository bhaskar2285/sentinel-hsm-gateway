package com.isc.sentinel.api.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class HmacGenRequest {
    /** UUID of HMAC key under LMK. */
    @NotBlank private String keyId;

    /** Data to authenticate, hex-encoded. */
    @NotBlank private String dataHex;

    /** Hash algorithm: "06"=SHA-256 (default). */
    private String hashId = "06";

    /** Requested HMAC output length in bytes, 4N e.g. "0020"=32 bytes. */
    private String hmacLen = "0020";
}
