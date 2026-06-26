package com.isc.sentinel.api.dto;

import lombok.Data;

@Data
public class KeyComponentGenRequest {
    /** Key scheme: U=double-length 3DES, X=single-DES, etc. (default "U"). */
    private String scheme = "U";

    /** Variant key type code of the component (e.g. 000=ZMK, 00A=DATA). Key Block LMK: "FFF". */
    private String keyType = "000";
}
