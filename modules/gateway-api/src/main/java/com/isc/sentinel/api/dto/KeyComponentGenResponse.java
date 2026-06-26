package com.isc.sentinel.api.dto;

import lombok.Data;

@Data
public class KeyComponentGenResponse {
    private String errCode;
    private String scheme;
    private String component;
    /** Component key check value (6 hex) — returned when the HSM check flag = '2'. */
    private String kcv;
}
