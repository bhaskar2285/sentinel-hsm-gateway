package com.isc.sentinel.api.dto;

import lombok.Data;

@Data
public class KeyComponentGenResponse {
    private String errCode;
    private String scheme;
    private String component;
}
