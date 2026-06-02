package com.isc.sentinel.api.dto;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class CscVerifyResponse {
    /** "0"=pass, "1"=absent/skipped, "2"=fail. */
    private String result5;
    private String result4;
    private String result3;
    /** true if at least csc3 verified. */
    private boolean verified;
    private String status;
    private String errCode;
    private String errText;
    private long   latencyMs;
}
