package com.isc.sentinel.api.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class DecryptRequest {
    @NotBlank
    private String keyId;

    @NotBlank
    private String ciphertextHex;

    /** "00"=ECB "01"=CBC "02"=CFB */
    private String mode = "01";

    /** Hex, 16 chars for DES, 32 for AES (CBC only). */
    private String iv;

    /** "0"=hex input, "1"=binary */
    private String inputFormat = "0";
    private String outputFormat = "0";
}
