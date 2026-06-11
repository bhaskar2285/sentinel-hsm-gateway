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
        OpCode.KEY_GEN,
        OpCode.KEY_IMPORT_RSA_WRAPPED,
        OpCode.KEY_IMPORT_ZMK,
        OpCode.KEY_EXPORT,
        OpCode.KEY_FORM_BLOCK,
        OpCode.DATA_ENCRYPT,
        OpCode.DATA_DECRYPT,
        OpCode.PIN_TRANSLATE,
        OpCode.PIN_VERIFY,
        OpCode.CVV_GEN,
        OpCode.CVV_VERIFY,
        OpCode.ARQC_VERIFY,
        // Phase 2
        OpCode.PIN_GEN,
        OpCode.PVV_GEN,
        OpCode.IBM_OFFSET_GEN,
        OpCode.PIN_VERIFY_VISA,
        OpCode.INTERCHANGE_PIN_VERIFY_IBM,
        OpCode.INTERCHANGE_PIN_VERIFY_VISA,
        OpCode.PIN_TRANSLATE_ZPK,
        OpCode.CLEAR_PIN_ENCRYPT,
        OpCode.PIN_DERIVE_IBM,
        OpCode.MAC_GEN,
        OpCode.MAC_VERIFY,
        OpCode.KEY_EXPORT_ZMK,
        OpCode.PIN_TO_LMK,
        OpCode.PIN_FROM_LMK,
        OpCode.KEY_COMPONENT_GEN,
        OpCode.KEY_FORM_COMPONENTS,
        OpCode.KEY_CHECK_VALUE,
        OpCode.HSM_ECHO,
        OpCode.ARQC_VERIFY_EMV4,
        OpCode.HSM_STATUS,
        OpCode.DCVV_VERIFY,
        OpCode.CSC_CALC,
        OpCode.CSC_VERIFY,
        OpCode.HMAC_GEN,
        OpCode.HMAC_VERIFY,
        OpCode.KEY_GEN_TPK,
        OpCode.KEY_GEN_ZPK,
        OpCode.PIN_DECRYPT,
        OpCode.RANDOM_DATA,
        OpCode.PIN_TRANSLATE_ZPK2,
        OpCode.MAC_VERIFY_ALT,
        OpCode.NET_HEALTH
    );

    private final ThalesTransport transport;
    private final HsmHeader header;
    private final int connectTimeoutMs;

    public ThalesVendorAdapter(
        @Value("${sentinel.thales.connect-timeout-ms:5000}") int connectTimeoutMs,
        @Value("${sentinel.thales.read-timeout-ms:10000}")   int readTimeoutMs,
        @Value("${sentinel.thales.pool-max-per-node:8}")     int maxPerNode,
        @Value("${sentinel.thales.header:SENT}")             String headerText,
        @Value("${sentinel.thales.tls.enabled:false}")       boolean tls,
        @Value("${sentinel.thales.tls.insecure-skip-verify:false}") boolean tlsInsecureSkipVerify
    ) {
        this.connectTimeoutMs = connectTimeoutMs;
        this.transport = new ThalesTransport(connectTimeoutMs, readTimeoutMs, maxPerNode, tls, tlsInsecureSkipVerify);
        this.header = new HsmHeader(headerText);
    }

    @Override public HsmVendor vendor() { return HsmVendor.THALES; }

    public void reloadNode(Long nodeId) { transport.evictNode(nodeId); }

    @Override public boolean supports(OpCode op) { return SUPPORTED.contains(op); }

    @Override
    public GatewayResponse execute(GatewayCommand cmd, HsmNodeRef node) {
        long start = System.currentTimeMillis();
        try {
            HsmWireMessage req = buildRequest(cmd);
            byte[] wireBytes = req.toWireBytes();
            if (log.isDebugEnabled()) {
                log.debug("HSM TX op={} node={} hex={}", cmd.getOp(), node.getId(),
                    java.util.HexFormat.of().withUpperCase().formatHex(wireBytes));
            }
            byte[] respBody = transport.roundTrip(node, wireBytes);
            if (log.isDebugEnabled()) {
                log.debug("HSM RX op={} node={} hex={}", cmd.getOp(), node.getId(),
                    java.util.HexFormat.of().withUpperCase().formatHex(respBody));
            }
            Phase1Parser.Parsed parsed = Phase1Parser.parse(respBody, header.length(), expectedResponse(cmd));

            String status = "00".equals(parsed.errorCode()) ? "OK" : "ERROR";
            if (!"00".equals(parsed.errorCode())) {
                log.warn("HSM error op={} node={} errCode={} errText={} TX={}", cmd.getOp(), node.getId(),
                    parsed.errorCode(), ThalesErrorCode.describe(parsed.errorCode()),
                    new String(wireBytes, java.nio.charset.StandardCharsets.US_ASCII).substring(2));
            }
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
            case RSA_KEY_GEN                 -> Phase1Builder.buildEI(header, cmd.getParams());
            case KEY_GEN                     -> Phase1Builder.buildA0(header, cmd.getParams());
            case KEY_IMPORT_RSA_WRAPPED      -> Phase1Builder.buildGI(header, cmd.getParams());
            case KEY_IMPORT_ZMK              -> Phase1Builder.buildA6(header, cmd.getParams());
            case KEY_EXPORT                  -> Phase1Builder.buildA8(header, cmd.getParams());
            case KEY_FORM_BLOCK              -> Phase1Builder.buildB4(header, cmd.getParams());
            case DATA_ENCRYPT                -> Phase1Builder.buildM0(header, cmd.getParams());
            case DATA_DECRYPT                -> Phase1Builder.buildM2(header, cmd.getParams());
            case PIN_TRANSLATE               -> Phase1Builder.buildCA(header, cmd.getParams());
            case PIN_VERIFY                  -> Phase1Builder.buildDA(header, cmd.getParams());
            case CVV_GEN                     -> Phase1Builder.buildCW(header, cmd.getParams());
            case CVV_VERIFY                  -> Phase1Builder.buildCY(header, cmd.getParams());
            case ARQC_VERIFY                 -> Phase1Builder.buildKQ(header, cmd.getParams());
            case PIN_GEN                     -> Phase1Builder.buildJA(header, cmd.getParams());
            case PVV_GEN                     -> Phase1Builder.buildDG(header, cmd.getParams());
            case IBM_OFFSET_GEN              -> Phase1Builder.buildDE(header, cmd.getParams());
            case PIN_VERIFY_VISA             -> Phase1Builder.buildDC(header, cmd.getParams());
            case INTERCHANGE_PIN_VERIFY_IBM  -> Phase1Builder.buildEA(header, cmd.getParams());
            case INTERCHANGE_PIN_VERIFY_VISA -> Phase1Builder.buildEC(header, cmd.getParams());
            case PIN_TRANSLATE_ZPK           -> Phase1Builder.buildCC(header, cmd.getParams());
            case CLEAR_PIN_ENCRYPT           -> Phase1Builder.buildBA(header, cmd.getParams());
            case PIN_DERIVE_IBM              -> Phase1Builder.buildEE(header, cmd.getParams());
            case MAC_GEN                     -> Phase1Builder.buildM6(header, cmd.getParams());
            case MAC_VERIFY                  -> Phase1Builder.buildM8(header, cmd.getParams());
            case KEY_EXPORT_ZMK              -> Phase1Builder.buildGC(header, cmd.getParams());
            case PIN_TO_LMK                  -> "ZPK".equals(cmd.getParams().get("inputKeyScheme"))
                                                 ? Phase1Builder.buildJE(header, cmd.getParams())
                                                 : Phase1Builder.buildJC(header, cmd.getParams());
            case PIN_FROM_LMK                -> Phase1Builder.buildJG(header, cmd.getParams());
            case KEY_COMPONENT_GEN           -> Phase1Builder.buildA2(header, cmd.getParams());
            case KEY_FORM_COMPONENTS         -> Phase1Builder.buildA4(header, cmd.getParams());
            case KEY_CHECK_VALUE             -> Phase1Builder.buildBU(header, cmd.getParams());
            case HSM_ECHO                    -> Phase1Builder.buildB2(header, cmd.getParams());
            case HSM_STATUS                  -> Phase1Builder.buildNO(header, cmd.getParams());
            case ARQC_VERIFY_EMV4            -> Phase1Builder.buildKW(header, cmd.getParams());
            case DCVV_VERIFY                 -> Phase1Builder.buildPM(header, cmd.getParams());
            case CSC_CALC                    -> Phase1Builder.buildRY(header, cmd.getParams());
            case CSC_VERIFY                  -> Phase1Builder.buildRY(header, cmd.getParams());
            case HMAC_GEN                    -> Phase1Builder.buildLQ(header, cmd.getParams());
            case HMAC_VERIFY                 -> Phase1Builder.buildLS(header, cmd.getParams());
            case KEY_GEN_TPK                 -> Phase1Builder.buildHC(header, cmd.getParams());
            case KEY_GEN_ZPK                 -> Phase1Builder.buildIA(header, cmd.getParams());
            case PIN_DECRYPT                 -> Phase1Builder.buildNG(header, cmd.getParams());
            case RANDOM_DATA                 -> Phase1Builder.buildOA(header, cmd.getParams());
            case PIN_TRANSLATE_ZPK2          -> Phase1Builder.buildJS(header, cmd.getParams());
            case MAC_VERIFY_ALT              -> Phase1Builder.buildVA(header, cmd.getParams());
            case NET_HEALTH                  -> Phase1Builder.buildNC(header, cmd.getParams());
            default -> throw new UnsupportedOperationException("Thales op not supported: " + cmd.getOp());
        };
    }

    private String expectedResponse(GatewayCommand cmd) {
        return switch (cmd.getOp()) {
            case RSA_KEY_GEN                 -> ThalesCommandCode.EI.response();
            case KEY_GEN                     -> ThalesCommandCode.A0.response();
            case KEY_IMPORT_RSA_WRAPPED      -> ThalesCommandCode.GI.response();
            case KEY_IMPORT_ZMK              -> ThalesCommandCode.A6.response();
            case KEY_EXPORT                  -> ThalesCommandCode.A8.response();
            case KEY_FORM_BLOCK              -> ThalesCommandCode.B4.response();
            case DATA_ENCRYPT                -> ThalesCommandCode.M0.response();
            case DATA_DECRYPT                -> ThalesCommandCode.M2.response();
            case PIN_TRANSLATE               -> ThalesCommandCode.CA.response();
            case PIN_VERIFY                  -> ThalesCommandCode.DA.response();
            case CVV_GEN                     -> ThalesCommandCode.CW.response();
            case CVV_VERIFY                  -> ThalesCommandCode.CY.response();
            case ARQC_VERIFY                 -> ThalesCommandCode.KQ.response();
            case PIN_GEN                     -> ThalesCommandCode.JA.response();
            case PVV_GEN                     -> ThalesCommandCode.DG.response();
            case IBM_OFFSET_GEN              -> ThalesCommandCode.DE.response();
            case PIN_VERIFY_VISA             -> ThalesCommandCode.DC.response();
            case INTERCHANGE_PIN_VERIFY_IBM  -> ThalesCommandCode.EA.response();
            case INTERCHANGE_PIN_VERIFY_VISA -> ThalesCommandCode.EC.response();
            case PIN_TRANSLATE_ZPK           -> ThalesCommandCode.CC.response();
            case CLEAR_PIN_ENCRYPT           -> ThalesCommandCode.BA.response();
            case PIN_DERIVE_IBM              -> ThalesCommandCode.EE.response();
            case MAC_GEN                     -> ThalesCommandCode.M6.response();
            case MAC_VERIFY                  -> ThalesCommandCode.M8.response();
            case KEY_EXPORT_ZMK              -> ThalesCommandCode.GC.response();
            case PIN_TO_LMK                  -> "ZPK".equals(cmd.getParams().get("inputKeyScheme"))
                                                 ? ThalesCommandCode.JE.response()
                                                 : ThalesCommandCode.JC.response();
            case PIN_FROM_LMK                -> ThalesCommandCode.JG.response();
            case KEY_COMPONENT_GEN           -> ThalesCommandCode.A2.response();
            case KEY_FORM_COMPONENTS         -> ThalesCommandCode.A4.response();
            case KEY_CHECK_VALUE             -> ThalesCommandCode.BU.response();
            case HSM_ECHO                    -> ThalesCommandCode.B2.response();
            case HSM_STATUS                  -> ThalesCommandCode.NO.response();
            case ARQC_VERIFY_EMV4            -> ThalesCommandCode.KW.response();
            case DCVV_VERIFY                 -> ThalesCommandCode.PM.response();
            case CSC_CALC                    -> ThalesCommandCode.RY.response();
            case CSC_VERIFY                  -> ThalesCommandCode.RY.response();
            case HMAC_GEN                    -> ThalesCommandCode.LQ.response();
            case HMAC_VERIFY                 -> ThalesCommandCode.LS.response();
            case KEY_GEN_TPK                 -> ThalesCommandCode.HC.response();
            case KEY_GEN_ZPK                 -> ThalesCommandCode.IA.response();
            case PIN_DECRYPT                 -> ThalesCommandCode.NG.response();
            case RANDOM_DATA                 -> ThalesCommandCode.OA.response();
            case PIN_TRANSLATE_ZPK2          -> ThalesCommandCode.JS.response();
            case MAC_VERIFY_ALT              -> ThalesCommandCode.VA.response();
            case NET_HEALTH                  -> ThalesCommandCode.NC.response();
            default -> throw new UnsupportedOperationException("no Thales mapping: " + cmd.getOp());
        };
    }

    @Override
    public boolean health(HsmNodeRef node) {
        try (java.net.Socket s = new java.net.Socket()) {
            s.connect(new java.net.InetSocketAddress(node.getHost(), node.getPort()), connectTimeoutMs);
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
