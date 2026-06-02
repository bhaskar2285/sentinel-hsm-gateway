package com.isc.sentinel.api.dto;

import lombok.Data;

@Data
public class HsmEchoRequest {
    /** Data to echo back from the HSM (ASCII, default "PING"). */
    private String data = "PING";
}
