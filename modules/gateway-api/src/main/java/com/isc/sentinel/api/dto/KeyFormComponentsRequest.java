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

    /** Encrypted components (each = LMK-encrypted component, e.g. "U"+32H), min 2. */
    @NotEmpty
    private List<String> components;

    /** Vault label for the formed key. If set, the key is persisted and a keyId returned. */
    private String label;

    /** Usage tag stored with the persisted key. */
    private String usage = "ENC,DEC";
}
