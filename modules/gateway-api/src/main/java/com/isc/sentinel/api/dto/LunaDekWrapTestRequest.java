package com.isc.sentinel.api.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

import java.util.List;

/**
 * TEST helper input — build a {@code dekBlob} (clear DEK wrapped under a clear ZMK) for
 * /luna/dek/import without ITMX. Provide either the ZMK components or the clear ZMK hex.
 */
@Data
public class LunaDekWrapTestRequest {
    /** Clear ZMK components (hex, XOR'd into the ZMK). Use this OR {@code zmkHex}. */
    private List<String> components;

    /** Clear ZMK (hex). Use this OR {@code components}. */
    private String zmkHex;

    /** Clear DEK to wrap (hex). */
    @NotBlank
    private String dekHex;

    /** JCA algorithm (default 3DES). */
    private String algorithm = "DESede";
}
