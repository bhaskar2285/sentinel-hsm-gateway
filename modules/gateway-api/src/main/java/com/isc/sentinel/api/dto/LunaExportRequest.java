package com.isc.sentinel.api.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

/**
 * Luna-native export of a stored Luna key (KBPK/ZMK/DEK) as a TR-31 key block under a
 * transport KBPK. Replaces the Thales A8/A9 export path for Luna keys.
 */
@Data
public class LunaExportRequest {
    /** keyUuid of the Luna key to export. */
    @NotBlank
    private String keyId;

    /** keyUuid of the transport KBPK that wraps the export. */
    @NotBlank
    private String transportKbpkId;

    /** TR-31 key usage for the exported key (default K0 = key-encryption key). */
    private String keyUsage = "K0";
}
