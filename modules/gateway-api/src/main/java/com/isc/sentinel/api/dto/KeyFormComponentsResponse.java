package com.isc.sentinel.api.dto;

import lombok.Data;

@Data
public class KeyFormComponentsResponse {
    private String errCode;
    private String scheme;
    private String keyUnderLmk;
    private String kcv;
    /** UUID of the persisted formed key (present only when a label was supplied). */
    private String keyId;
}
