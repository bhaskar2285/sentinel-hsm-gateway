package com.isc.sentinel.vendor.thales.command;

import com.isc.sentinel.vendor.thales.wire.HsmHeader;
import com.isc.sentinel.vendor.thales.wire.HsmWireMessage;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Locks the wire layout of the specialised "legacy" commands against the payShield
 * Core Host Commands manual. PA/PC/PE/BG cannot be live-verified in this environment
 * (printer / Key-Change LMK), so these tests are the spec contract. body() excludes
 * the 2-char command code.
 */
class LegacyCmdWireTest {

    private static final HsmHeader HDR = new HsmHeader("RSM5");
    private static String body(HsmWireMessage m) {
        return new String(m.body(), StandardCharsets.US_ASCII);
    }

    @Test void buildPA_isRawData() {                 // p.235
        assertEquals("01ABC", body(ThalesCmdBuilder.buildPA(HDR, Map.of("data", "01ABC"))));
    }

    @Test void buildPC_isRawData() {                 // p.236
        assertEquals("ZZ9", body(ThalesCmdBuilder.buildPC(HDR, Map.of("data", "ZZ9"))));
    }

    @Test void buildPE_docTypeAcctPinFields() {      // p.224
        HsmWireMessage m = ThalesCmdBuilder.buildPE(HDR, Map.of(
            "documentType", "C", "pan", "4000001234560000",
            "pinUnderLmk", "8699636332605",
            "printFields", List.of("JOHN SMITH", "12 MAIN ST")));
        assertEquals("C" + "000123456000" + "8699636332605" + "JOHN SMITH;12 MAIN ST", body(m));
    }

    @Test void buildBG_acctThenOldLmkPin() {         // p.69
        HsmWireMessage m = ThalesCmdBuilder.buildBG(HDR, Map.of(
            "pan", "4000001234560000", "pinUnderLmk", "8699636332605"));
        assertEquals("000123456000" + "8699636332605", body(m));
    }

    @Test void buildG0_dukptTranslate_zpkDest() {    // p.339 (3DES, ZPK dest, no dst KSN)
        String bdk = "0123456789ABCDEF0123456789ABCDEF";
        String zpk = "FEDCBA9876543210FEDCBA9876543210";
        HsmWireMessage m = ThalesCmdBuilder.buildG0(HDR, Map.of(
            "srcBdkHex", bdk, "dstKeyHex", zpk,
            "srcKsnDescriptor", "605", "srcKsn", "FFFF9876543210E00001",
            "pinBlock", "0123456789ABCDEF", "pinBlockFormat", "01",
            "dstPinBlockFormat", "01", "pan", "4000001234560000"));
        assertEquals("U" + bdk + "U" + zpk + "605" + "FFFF9876543210E00001"
                     + "0123456789ABCDEF" + "01" + "01" + "000123456000", body(m));
    }

    @Test void buildGO_dukptPinVerify_mode0() {      // p.344 (Mode 0, IBM offset)
        String bdk = "0123456789ABCDEF0123456789ABCDEF";
        String pvk = "FEDCBA9876543210FEDCBA9876543210";
        java.util.Map<String, Object> p = new java.util.HashMap<>();
        p.put("mode", "0"); p.put("bdkHex", bdk); p.put("pvkHex", pvk);
        p.put("ksnDescriptor", "605"); p.put("ksn", "FFFF9876543210E00001");
        p.put("pinBlock", "0123456789ABCDEF"); p.put("pinBlockFormat", "01"); p.put("checkLen", "4");
        p.put("pan", "4000001234560000"); p.put("decimTable", "0123456789012345");
        p.put("pinValidData", "000123456000"); p.put("pinOffset", "FFFFFFFFFFFF");
        HsmWireMessage m = ThalesCmdBuilder.buildGO(HDR, p);
        assertEquals("0" + "U" + bdk + "U" + pvk + "605" + "FFFF9876543210E00001"
                     + "0123456789ABCDEF" + "01" + "04" + "000123456000"
                     + "0123456789012345" + "000123456000" + "FFFFFFFFFFFF", body(m));
    }

    @Test void parseG1_pinBlockAndFormat() {
        String wire = "RSM5G100" + "1122334455667788" + "01";
        ThalesCmdParser.Parsed p =
            ThalesCmdParser.parse(wire.getBytes(StandardCharsets.US_ASCII), 4, "G1");
        assertEquals("00", p.errorCode());
        assertEquals("1122334455667788", p.fields().get("pinBlock"));
        assertEquals("01", p.fields().get("pinBlockFormat"));
    }
}
