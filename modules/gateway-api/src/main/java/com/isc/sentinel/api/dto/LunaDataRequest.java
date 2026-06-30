package com.isc.sentinel.api.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

/** Luna encrypt/decrypt of a hex block under a registered DEK (unwrapped per op inside the HSM). */
@Data
public class LunaDataRequest {
    /** keyUuid of the registered DEK. */
    @NotBlank
    private String keyId;

    /** Data block (hex). For 3DES/ECB this is an 8- or 16-byte block. */
    @NotBlank
    private String data;

    /** Cipher transformation (default 3DES ECB, no padding). */
    private String transformation = "DESede/ECB/NoPadding";

    /** IV (hex) for CBC/CTR modes; ignored for ECB. */
    private String iv;
}
