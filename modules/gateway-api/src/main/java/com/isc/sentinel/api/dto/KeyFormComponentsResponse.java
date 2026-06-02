package com.isc.sentinel.api.dto;

import lombok.Data;

@Data
public class KeyFormComponentsResponse {
    private String errCode;
    private String scheme;
    private String keyUnderLmk;
    private String kcv;
}
