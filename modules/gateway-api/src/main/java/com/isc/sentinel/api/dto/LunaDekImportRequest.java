package com.isc.sentinel.api.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

/** Luna ceremony: register a DEK delivered already wrapped under the ZMK. */
@Data
public class LunaDekImportRequest {
    /** keyUuid of the previously-formed ZMK that unwraps this DEK. */
    @NotBlank
    private String zmkKeyId;

    /** DEK ciphertext (hex) = DEK wrapped under the ZMK. */
    @NotBlank
    private String dekBlob;

    /** KEK cipher transformation used to unwrap (default 3DES ECB). */
    private String wrapMech = "DESede";

    /** JCA algorithm of the unwrapped DEK (default 3DES). */
    private String algorithm = "DESede";

    /** Vault label for the registered DEK. */
    @NotBlank
    private String label;
}
