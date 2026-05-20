package com.isc.sentinel.spi;

import lombok.Builder;
import lombok.Value;

import java.util.Map;

/**
 * Vendor-neutral command. Adapter consumes this + produces wire bytes.
 * params is open-ended so each op can carry op-specific fields (modulusBits, mode, iv, ...).
 */
@Value
@Builder
public class GatewayCommand {
    OpCode op;
    HsmVendor vendorHint;       // null = router decides
    String keyId;                // logical key id, optional
    Map<String, Object> params;  // op-specific
    String traceId;
    String userId;
}
