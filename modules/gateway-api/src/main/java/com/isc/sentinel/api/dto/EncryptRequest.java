package com.isc.sentinel.api.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class EncryptRequest {
    @NotBlank private String keyId;

    /** "00"=ECB, "01"=CBC. */
    private String mode = "01";

    /** 16-byte (32 hex) IV; required for CBC. */
    private String iv;

    /** Plaintext hex. Must be a multiple of cipher block size (no auto-pad). */
    @NotBlank private String plaintextHex;

    /** Thales key family hint. Optional. */
    private String keyType = "00A";
}
