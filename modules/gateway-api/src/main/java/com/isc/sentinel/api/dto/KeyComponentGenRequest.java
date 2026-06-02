package com.isc.sentinel.api.dto;

import lombok.Data;

@Data
public class KeyComponentGenRequest {
    /** Key scheme: U=double-length 3DES, X=single-DES, etc. (default "U"). */
    private String scheme = "U";
}
