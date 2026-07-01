package com.isc.sentinel.api.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

/** Compute the KCV of a clear key value (e.g. a ZMK custodian component). */
@Data
public class LunaKcvRequest {
    /** Clear key value (hex). */
    @NotBlank
    private String valueHex;

    /** JCA algorithm (default 3DES). */
    private String algorithm = "DESede";
}
