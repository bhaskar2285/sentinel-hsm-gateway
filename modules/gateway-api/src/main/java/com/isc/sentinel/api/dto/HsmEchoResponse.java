package com.isc.sentinel.api.dto;

import lombok.Data;

@Data
public class HsmEchoResponse {
    private String errCode;
    private String echo;
}
