package com.isc.sentinel.api.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class KeyCheckValueRequest {
    /** UUID of key to generate check value for. */
    @NotBlank private String keyId;

    /** Key type override (3H). If omitted, derived from key record. */
    private String keyType;
}
