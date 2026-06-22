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

    /** Input ciphertext format: "0" => message carried as binary on the wire (the
     *  gateway always binarises the supplied ciphertextHex). */
    private String inputFormat = "0";
    /** Output plaintext format: "1" => HSM returns the plaintext as hex so the API
     *  field plaintextHex is hex (UI-displayable); "0" would return raw binary. */
    private String outputFormat = "1";
}
