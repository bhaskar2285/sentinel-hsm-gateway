package com.isc.sentinel.spi;

/**
 * SPI implemented by each vendor module (Thales, Utimaco, ...).
 *
 * Lifecycle:
 *   1. dispatcher routes GatewayCommand to adapter matching vendor()
 *   2. adapter.buildRequest() — serialize to vendor wire format
 *   3. adapter.send() — send to HsmNodeRef (uses vendor-managed pool/transport)
 *   4. adapter.parseResponse() — decode wire bytes to GatewayResponse
 *
 * Implementations should be Spring beans (@Component).
 */
public interface HsmVendorAdapter {

    HsmVendor vendor();

    boolean supports(OpCode op);

    /** Execute end-to-end: build → send → parse. Adapter owns transport. */
    GatewayResponse execute(GatewayCommand command, HsmNodeRef node);

    /** Health check command. */
    boolean health(HsmNodeRef node);
}
