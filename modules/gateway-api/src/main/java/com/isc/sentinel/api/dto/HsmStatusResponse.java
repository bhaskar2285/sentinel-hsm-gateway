package com.isc.sentinel.api.dto;

import lombok.Data;

@Data
public class HsmStatusResponse {
    private String errCode;
    private String lmkCheckValue;
    private String firmware;
    private String dspFirmware;
    private String sequence;
    private String flags;
}
