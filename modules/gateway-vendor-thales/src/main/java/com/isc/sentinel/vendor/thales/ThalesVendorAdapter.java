package com.isc.sentinel.vendor.thales;

import com.isc.sentinel.spi.*;
import com.isc.sentinel.vendor.thales.command.ThalesCmdBuilder;
import com.isc.sentinel.vendor.thales.command.ThalesCmdParser;
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
        OpCode.NET_HEALTH,
        OpCode.FORMATTING_DATA_LOAD,
        OpCode.FORMATTING_DATA_ADD,
        OpCode.PIN_MAILER_PRINT,
        OpCode.PIN_MIGRATE_LMK,
        OpCode.DUKPT_PIN_TRANSLATE,
        OpCode.DUKPT_PIN_VERIFY
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
            ThalesCmdParser.Parsed parsed = ThalesCmdParser.parse(respBody, header.length(), expectedResponse(cmd));

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
            case RSA_KEY_GEN                 -> ThalesCmdBuilder.buildEI(header, cmd.getParams());
            case KEY_GEN                     -> ThalesCmdBuilder.buildA0(header, cmd.getParams());
            case KEY_IMPORT_RSA_WRAPPED      -> ThalesCmdBuilder.buildGI(header, cmd.getParams());
            case KEY_IMPORT_ZMK              -> ThalesCmdBuilder.buildA6(header, cmd.getParams());
            case KEY_EXPORT                  -> ThalesCmdBuilder.buildA8(header, cmd.getParams());
            case KEY_FORM_BLOCK              -> ThalesCmdBuilder.buildB4(header, cmd.getParams());
            case DATA_ENCRYPT                -> ThalesCmdBuilder.buildM0(header, cmd.getParams());
            case DATA_DECRYPT                -> ThalesCmdBuilder.buildM2(header, cmd.getParams());
            case PIN_TRANSLATE               -> ThalesCmdBuilder.buildCA(header, cmd.getParams());
            case PIN_VERIFY                  -> ThalesCmdBuilder.buildDA(header, cmd.getParams());
            case CVV_GEN                     -> ThalesCmdBuilder.buildCW(header, cmd.getParams());
            case CVV_VERIFY                  -> ThalesCmdBuilder.buildCY(header, cmd.getParams());
            case ARQC_VERIFY                 -> ThalesCmdBuilder.buildKQ(header, cmd.getParams());
            case PIN_GEN                     -> ThalesCmdBuilder.buildJA(header, cmd.getParams());
            case PVV_GEN                     -> ThalesCmdBuilder.buildDG(header, cmd.getParams());
            case IBM_OFFSET_GEN              -> ThalesCmdBuilder.buildDE(header, cmd.getParams());
            case PIN_VERIFY_VISA             -> ThalesCmdBuilder.buildDC(header, cmd.getParams());
            case INTERCHANGE_PIN_VERIFY_IBM  -> ThalesCmdBuilder.buildEA(header, cmd.getParams());
            case INTERCHANGE_PIN_VERIFY_VISA -> ThalesCmdBuilder.buildEC(header, cmd.getParams());
            case PIN_TRANSLATE_ZPK           -> ThalesCmdBuilder.buildCC(header, cmd.getParams());
            case CLEAR_PIN_ENCRYPT           -> ThalesCmdBuilder.buildBA(header, cmd.getParams());
            case PIN_DERIVE_IBM              -> ThalesCmdBuilder.buildEE(header, cmd.getParams());
            case MAC_GEN                     -> ThalesCmdBuilder.buildM6(header, cmd.getParams());
            case MAC_VERIFY                  -> ThalesCmdBuilder.buildM8(header, cmd.getParams());
            case KEY_EXPORT_ZMK              -> ThalesCmdBuilder.buildGC(header, cmd.getParams());
            case PIN_TO_LMK                  -> "ZPK".equals(cmd.getParams().get("inputKeyScheme"))
                                                 ? ThalesCmdBuilder.buildJE(header, cmd.getParams())
                                                 : ThalesCmdBuilder.buildJC(header, cmd.getParams());
            case PIN_FROM_LMK                -> ThalesCmdBuilder.buildJG(header, cmd.getParams());
            case KEY_COMPONENT_GEN           -> ThalesCmdBuilder.buildA2(header, cmd.getParams());
            case KEY_FORM_COMPONENTS         -> ThalesCmdBuilder.buildA4(header, cmd.getParams());
            case KEY_CHECK_VALUE             -> ThalesCmdBuilder.buildBU(header, cmd.getParams());
            case HSM_ECHO                    -> ThalesCmdBuilder.buildB2(header, cmd.getParams());
            case HSM_STATUS                  -> ThalesCmdBuilder.buildNO(header, cmd.getParams());
            case ARQC_VERIFY_EMV4            -> ThalesCmdBuilder.buildKW(header, cmd.getParams());
            case DCVV_VERIFY                 -> ThalesCmdBuilder.buildPM(header, cmd.getParams());
            case CSC_CALC                    -> ThalesCmdBuilder.buildRY(header, cmd.getParams());
            case CSC_VERIFY                  -> ThalesCmdBuilder.buildRY(header, cmd.getParams());
            case HMAC_GEN                    -> ThalesCmdBuilder.buildLQ(header, cmd.getParams());
            case HMAC_VERIFY                 -> ThalesCmdBuilder.buildLS(header, cmd.getParams());
            case KEY_GEN_TPK                 -> ThalesCmdBuilder.buildHC(header, cmd.getParams());
            case KEY_GEN_ZPK                 -> ThalesCmdBuilder.buildIA(header, cmd.getParams());
            case PIN_DECRYPT                 -> ThalesCmdBuilder.buildNG(header, cmd.getParams());
            case RANDOM_DATA                 -> ThalesCmdBuilder.buildOA(header, cmd.getParams());
            case PIN_TRANSLATE_ZPK2          -> ThalesCmdBuilder.buildJS(header, cmd.getParams());
            case MAC_VERIFY_ALT              -> ThalesCmdBuilder.buildVA(header, cmd.getParams());
            case NET_HEALTH                  -> ThalesCmdBuilder.buildNC(header, cmd.getParams());
            case FORMATTING_DATA_LOAD        -> ThalesCmdBuilder.buildPA(header, cmd.getParams());
            case FORMATTING_DATA_ADD         -> ThalesCmdBuilder.buildPC(header, cmd.getParams());
            case PIN_MAILER_PRINT            -> ThalesCmdBuilder.buildPE(header, cmd.getParams());
            case PIN_MIGRATE_LMK             -> ThalesCmdBuilder.buildBG(header, cmd.getParams());
            case DUKPT_PIN_TRANSLATE         -> ThalesCmdBuilder.buildG0(header, cmd.getParams());
            case DUKPT_PIN_VERIFY            -> ThalesCmdBuilder.buildGO(header, cmd.getParams());
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
            case FORMATTING_DATA_LOAD        -> ThalesCommandCode.PA.response();
            case FORMATTING_DATA_ADD         -> ThalesCommandCode.PC.response();
            case PIN_MAILER_PRINT            -> ThalesCommandCode.PE.response();
            case PIN_MIGRATE_LMK             -> ThalesCommandCode.BG.response();
            case DUKPT_PIN_TRANSLATE         -> ThalesCommandCode.G0.response();
            case DUKPT_PIN_VERIFY            -> ThalesCommandCode.GO.response();
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
