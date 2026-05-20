package com.isc.sentinel.keyblock;

import lombok.Builder;
import lombok.Value;

@Value
@Builder
public class KeyBlock {
    KeyBlockFormat format;
    String payload;        // ASCII key block (TR-31/X9.143) or hex (RAW)
    String kcv;            // 6-hex KCV
    String wrappingKeyId;  // KBPK reference (null when RAW)
}
