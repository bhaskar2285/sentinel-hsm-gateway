package com.isc.sentinel.vendor.utimaco;

import com.isc.sentinel.spi.*;
import org.springframework.stereotype.Component;

import java.util.Map;

/**
 * Utimaco vendor adapter stub. Phase 2+ implementation.
 * All ops return ERROR/UNSUPPORTED.
 */
@Component
public class UtimacoVendorAdapter implements HsmVendorAdapter {

    @Override public HsmVendor vendor() { return HsmVendor.UTIMACO; }

    @Override public boolean supports(OpCode op) { return false; }

    @Override
    public GatewayResponse execute(GatewayCommand cmd, HsmNodeRef node) {
        return GatewayResponse.builder()
            .op(cmd.getOp())
            .vendor(HsmVendor.UTIMACO)
            .hsmNodeId(node == null ? null : String.valueOf(node.getId()))
            .status("ERROR")
            .errCode("NI")
            .errText("Utimaco adapter not yet implemented")
            .latencyMs(0)
            .result(Map.of())
            .build();
    }

    @Override public boolean health(HsmNodeRef node) { return false; }
}
