package com.isc.sentinel.api.dto;

import lombok.Data;

/** A stored TR-31 key block, for the unwrap / crypto dropdowns. */
@Data
public class LunaTr31BlockSummary {
    private String keyId;          // keyUuid of the TR31_BLOCK row
    private String label;
    private String tr31Block;      // the key block (ASCII)
    private String header;         // first 16 chars
    private String version;        // B / D
    private String keyAlgorithm;   // wrapped key's algorithm (AES / DESede)
    private Integer keyBits;       // wrapped key length
    private String kbpkKeyId;      // keyUuid of the protecting KBPK
    private String kbpkLabel;
    private String createdAt;
}
