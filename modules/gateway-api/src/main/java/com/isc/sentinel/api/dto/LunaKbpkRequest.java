package com.isc.sentinel.api.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

/** Generate a Key Block Protection Key (KBPK) for TR-31 wrapping. */
@Data
public class LunaKbpkRequest {
    /** TR-31 key block version: "D" = AES, "B" = 3DES. */
    private String version = "D";

    /** Key size in bits. AES: 128/192/256; 3DES: 128/192. */
    private Integer keyBits = 256;

    /** Vault label for the KBPK. */
    @NotBlank
    private String label;
}
