package com.isc.sentinel.api.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

/**
 * Import a symmetric key that is currently wrapped under a ZMK held in the vault.
 * Sends Thales A6/A7.
 */
@Data
public class ImportZmkWrappedRequest {
    @NotBlank private String label;

    /** Thales 3-digit key family code for the imported key. */
    private String keyType = "001";

    /** UUID of the ZMK in the vault. */
    @NotBlank private String zmkKeyId;

    /** Hex of the imported key encrypted under the ZMK. Caller provides this. */
    @NotBlank private String keyUnderZmkHex;

    /** Scheme byte that prefixes the imported key (U/T/X/Y/Z or R/S/H). */
    private String keyScheme = "U";

    /** Output LMK scheme. */
    private String lmkScheme = "U";

    private String usage = "ENC,DEC";
    private String ownerOrg;
}
