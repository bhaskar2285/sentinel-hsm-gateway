package com.isc.sentinel.api.dto;

import jakarta.validation.constraints.NotEmpty;
import lombok.Data;
import java.util.List;

@Data
public class KeyFormComponentsRequest {
    /** Key type (3H), e.g. "001" for ZPK. */
    private String keyType = "001";

    /** Scheme for the resulting key under LMK (default "U"). */
    private String scheme = "U";

    /** List of clear components (each = schemePrefix + hex), min 2. */
    @NotEmpty
    private List<String> components;
}
