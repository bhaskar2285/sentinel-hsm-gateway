package com.isc.sentinel.vendor.thales;

import com.isc.sentinel.spi.*;
import com.isc.sentinel.vendor.thales.command.Phase1Builder;
import com.isc.sentinel.vendor.thales.command.Phase1Parser;
import com.isc.sentinel.vendor.thales.command.ThalesCommandCode;
import com.isc.sentinel.vendor.thales.command.ThalesErrorCode;
import com.isc.sentinel.vendor.thales.transport.ThalesTransport;
import com.isc.sentinel.vendor.thales.wire.HsmHeader;
import com.isc.sentinel.vendor.thales.wire.HsmWireMessage;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.Set;

@Slf4j
@Component
public class ThalesVendorAdapter implements HsmVendorAdapter, DisposableBean {

    private static final Set<OpCode> SUPPORTED = Set.of(
        OpCode.RSA_KEY_GEN,
        OpCode.KEY_IMPORT_RSA_WRAPPED,
        OpCode.KEY_EXPORT,
        OpCode.KEY_FORM_BLOCK,
        OpCode.DATA_DECRYPT
    );

    private final ThalesTransport transport;
    private final HsmHeader header;

    public ThalesVendorAdapter(
        @Value("${sentinel.thales.connect-timeout-ms:5000}") int connectTimeoutMs,
        @Value("${sentinel.thales.read-timeout-ms:10000}") int readTimeoutMs,
        @Value("${sentinel.thales.pool-max-per-node:8}") int maxPerNode,
        @Value("${sentinel.thales.header:SENT}") String headerText
    ) {
        this.transport = new ThalesTransport(connectTimeoutMs, readTimeoutMs, maxPerNode);
        this.header = new HsmHeader(headerText);
    }

    @Override public HsmVendor vendor() { return HsmVendor.THALES; }

    @Override public boolean supports(OpCode op) { return SUPPORTED.contains(op); }

    @Override
    public GatewayResponse execute(GatewayCommand cmd, HsmNodeRef node) {
        long start = System.currentTimeMillis();
        try {
            HsmWireMessage req = buildRequest(cmd);
            byte[] respBody = transport.roundTrip(node, req.toWireBytes());
            Phase1Parser.Parsed parsed = Phase1Parser.parse(respBody, header.length(), expectedResponse(cmd.getOp()));

            String status = "00".equals(parsed.errorCode()) ? "OK" : "ERROR";
            return GatewayResponse.builder()
                .op(cmd.getOp())
                .vendor(HsmVendor.THALES)
                .hsmNodeId(String.valueOf(node.getId()))
                .status(status)
                .errCode(parsed.errorCode())
                .errText(ThalesErrorCode.describe(parsed.errorCode()))
                .latencyMs(System.currentTimeMillis() - start)
                .result(parsed.fields())
                .build();

        } catch (Exception e) {
            log.error("Thales execute failed op={}, node={}", cmd.getOp(), node.getId(), e);
            return GatewayResponse.builder()
                .op(cmd.getOp())
                .vendor(HsmVendor.THALES)
                .hsmNodeId(String.valueOf(node.getId()))
                .status("ERROR")
                .errCode("EX")
                .errText(e.getMessage())
                .latencyMs(System.currentTimeMillis() - start)
                .result(Map.of())
                .build();
        }
    }

    private HsmWireMessage buildRequest(GatewayCommand cmd) {
        return switch (cmd.getOp()) {
            case RSA_KEY_GEN            -> Phase1Builder.buildEI(header, cmd.getParams());
            case KEY_IMPORT_RSA_WRAPPED -> Phase1Builder.buildGI(header, cmd.getParams());
            case KEY_EXPORT             -> Phase1Builder.buildA8(header, cmd.getParams());
            case KEY_FORM_BLOCK         -> Phase1Builder.buildB4(header, cmd.getParams());
            case DATA_DECRYPT           -> Phase1Builder.buildM2(header, cmd.getParams());
            default -> throw new UnsupportedOperationException("Thales op not supported: " + cmd.getOp());
        };
    }

    private String expectedResponse(OpCode op) {
        return switch (op) {
            case RSA_KEY_GEN            -> ThalesCommandCode.EI.response();
            case KEY_IMPORT_RSA_WRAPPED -> ThalesCommandCode.GI.response();
            case KEY_EXPORT             -> ThalesCommandCode.A8.response();
            case KEY_FORM_BLOCK         -> ThalesCommandCode.B4.response();
            case DATA_DECRYPT           -> ThalesCommandCode.M2.response();
            default -> throw new UnsupportedOperationException("no Thales mapping: " + op);
        };
    }

    @Override
    public boolean health(HsmNodeRef node) {
        // NC = HSM status (echo). TODO use real status cmd.
        try {
            byte[] hb = new HsmWireMessage(header, "NC", new byte[0], null).toWireBytes();
            transport.roundTrip(node, hb);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    @Override
    public void destroy() {
        transport.shutdown();
    }
}
