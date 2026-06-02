package com.isc.sentinel.api.dto;

import lombok.Data;

/** Generate random data (Thales OA/OB). */
@Data
public class RandomDataRequest {
    /** Output format: 0=hex, 1=binary (default 0, hex always returned). */
    private String format = "0";

    /** Number of random bytes to generate (1-256, default 16). */
    private int numBytes = 16;
}
