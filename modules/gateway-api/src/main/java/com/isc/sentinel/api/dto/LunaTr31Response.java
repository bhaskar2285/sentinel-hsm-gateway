package com.isc.sentinel.api.dto;

import lombok.Data;

/** Response for TR-31 wrap/unwrap. */
@Data
public class LunaTr31Response {
    /** Produced key block (wrap). */
    private String tr31Block;
    /** Recovered clear working key hex (unwrap). */
    private String workingKeyHex;
    /** Parsed 16-char TR-31 header. */
    private String header;
    /** Key block version (B/D). */
    private String version;
    /** keyUuid if the block/key was persisted. */
    private String keyId;
    private String errCode;
    private String errText;
}
