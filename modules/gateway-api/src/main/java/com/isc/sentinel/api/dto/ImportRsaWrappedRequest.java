package com.isc.sentinel.api.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class ImportRsaWrappedRequest {
    @NotBlank
    private String label;

    @NotBlank
    private String wrappingPublicKey;  // hex

    @NotBlank
    private String wrappedKey;         // hex

    private String mode = "0";
    private String hashId = "01";
    private String keyType;
    private String usage;
}
