package com.isc.sentinel.api.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

/**
 * Generate symmetric key under LMK (Thales A0/A1).
 *
 * keyType examples (Thales 3-digit family codes):
 *   000 = ZMK   (Zone Master Key)
 *   001 = ZPK   (Zone PIN Key)
 *   002 = PVK   (PIN Verification Key) / KBPK family
 *   008 = TMK   (Terminal Master Key)
 *   00A = generic data-encrypt key
 *
 * keyScheme: U/T/X/Y/Z (3DES variants) | R/S/H (AES variants).
 *   U = double-length 3DES (128b)
 *   T = triple-length 3DES (192b)
 *   R = AES-128
 *   S = AES-192
 *   H = AES-256
 */
@Data
public class SymKeyGenRequest {
    @NotBlank
    private String label;

    /** Key family code, see class javadoc. */
    private String keyType = "001";

    /** LMK scheme byte. */
    private String keyScheme = "U";

    /** "0" = key under LMK only; "1" = also wrap under ZMK and return. */
    private String mode = "0";

    /** Required when mode="1": UUID of an existing ZMK in the vault. */
    private String zmkKeyId;

    /** Output scheme byte for ZMK-wrapped copy (mode="1"). */
    private String outScheme = "U";

    private String usage = "WRAP,UNWRAP";

    private String ownerOrg;
}
