package com.isc.sentinel.api.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

/** Luna: generate a fresh random DEK in-HSM, wrapped under a stored ZMK. */
@Data
public class LunaDekGenRequest {
    /** keyUuid of the ZMK the new DEK is wrapped under. */
    @NotBlank
    private String zmkKeyId;

    /** JCA algorithm of the generated DEK (default 3DES). */
    private String algorithm = "DESede";

    /** AES key size in bits when algorithm=AES (ignored for DESede). */
    private Integer keyBits;

    /** Vault label for the generated DEK. */
    @NotBlank
    private String label;
}
