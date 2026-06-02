package com.isc.sentinel.api.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class HmacVerifyRequest {
    /** UUID of HMAC key under LMK. */
    @NotBlank private String keyId;

    /** Data that was authenticated, hex-encoded. */
    @NotBlank private String dataHex;

    /** HMAC to verify, hex-encoded. */
    @NotBlank private String hmac;

    /** Hash algorithm: "06"=SHA-256 (default). */
    private String hashId = "06";
}
