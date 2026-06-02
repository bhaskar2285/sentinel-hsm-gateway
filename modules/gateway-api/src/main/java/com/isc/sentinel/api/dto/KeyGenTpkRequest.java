package com.isc.sentinel.api.dto;

import lombok.Data;

/** Generate TPK under LMK (Thales HC/HD). */
@Data
public class KeyGenTpkRequest {
    private String keyScheme = "U";
    private String label;
    private String ownerOrg;
}
