package com.isc.sentinel.spi;

import lombok.Builder;
import lombok.Value;

import java.util.Map;

/**
 * Vendor-neutral parsed response.
 */
@Value
@Builder
public class GatewayResponse {
    OpCode op;
    HsmVendor vendor;
    String hsmNodeId;
    String status;               // "OK" | "ERROR" | "TIMEOUT"
    String errCode;              // vendor err code, mapped
    String errText;
    long   latencyMs;
    Map<String, Object> result;  // op-specific: publicKey, wrappedKey, plaintext, kcv...
}
