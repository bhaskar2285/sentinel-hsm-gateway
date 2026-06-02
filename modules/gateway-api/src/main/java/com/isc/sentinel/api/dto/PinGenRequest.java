package com.isc.sentinel.api.dto;

import lombok.Data;

@Data
public class PinGenRequest {
    /** PIN length, 4–12 digits (default "04"). */
    private String pinLen = "04";
}
