package com.isc.sentinel.vendor.thales.command;

import com.isc.sentinel.vendor.thales.wire.HsmHeader;
import com.isc.sentinel.vendor.thales.wire.HsmWireMessage;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Locks the corrected DC / JC / DE wire layouts against the real payShield Core Host
 * Commands manual and the TTB key-block trace. DC and JC previously carried a legacy
 * key-type / MaxPIN prefix (the same bug fixed earlier for DA/EA) which the real HSM
 * rejects with error 15. The HsmWireMessage.body() excludes the 2-char command code.
 */
class PinVerifyWireTest {

    private static final HsmHeader HDR = new HsmHeader("RSM5");

    private static String body(HsmWireMessage m) {
        return new String(m.body(), StandardCharsets.US_ASCII);
    }

    @Test
    void buildDC_noKeyTypePrefix_tpkThenPvk() {
        // Manual p.266: TPK + PVK + PINBlock(16H) + Fmt(2N) + PAN(12N) + PVKI(1N) + PVV(4N)
        String tpk = "0123456789ABCDEF0123456789ABCDEF";
        String pvk = "FEDCBA9876543210FEDCBA9876543210";
        String pinBlk = "0123456789ABCDEF";
        HsmWireMessage m = ThalesCmdBuilder.buildDC(HDR, Map.of(
            "tpkHex", tpk, "pvkHex", pvk, "pinBlock", pinBlk,
            "pinBlockFormat", "01", "pan", "4000001234560000",
            "pvki", "1", "pvv", "1234"));
        // U+tpk + U+pvk + pinblock + fmt + pan12(000123456000) + pvki + pvv
        assertEquals("U" + tpk + "U" + pvk + pinBlk + "01" + "000123456000" + "1" + "1234", body(m));
        assertFalse(body(m).startsWith("008"), "must not emit legacy key-type prefix");
    }

    @Test
    void buildJC_noKeyTypePrefix_tpkPinBlockFmtPan() {
        // Manual p.283: SourceTPK + PINBlock(16H) + Fmt(2N) + PAN(12N)
        String tpk = "0123456789ABCDEF0123456789ABCDEF";
        String pinBlk = "ABCDEF0123456789";
        HsmWireMessage m = ThalesCmdBuilder.buildJC(HDR, Map.of(
            "keyHex", tpk, "pinBlock", pinBlk,
            "pinBlockFormat", "01", "pan", "4000001234560000"));
        assertEquals("U" + tpk + pinBlk + "01" + "000123456000", body(m));
    }

    @Test
    void buildDE_matchesRealKeyBlockTraceOrder() {
        // TTB trace (DF02 success): DE + PVK(S-keyblock) + PIN(LN) + CheckLen(2) +
        // Acct(12) + DecimTable(16H) + 'P'+16H. Verify field ORDER with a scheme-U PVK.
        String pvk = "0123456789ABCDEF0123456789ABCDEF";
        String pinLmk = "8699636332605";              // 13-char LMK-encrypted PIN
        HsmWireMessage m = ThalesCmdBuilder.buildDE(HDR, Map.of(
            "pvkHex", pvk, "pinUnderLmk", pinLmk, "checkLen", "6",
            "pan", "617950000596", "decimTable", "1234567890123456",
            "pinValidData", "P50000596FFFFFFFF"));
        assertEquals("U" + pvk + pinLmk + "06" + "617950000596"
                     + "1234567890123456" + "P50000596FFFFFFFF", body(m));
    }

    @Test
    void parseJDReadsVariableLengthPin() {
        // Real JF: RSM5 JF 00 8699636332605  (13-char variable PIN, no length prefix)
        String wire = "RSM5JF008699636332605";
        ThalesCmdParser.Parsed p =
            ThalesCmdParser.parse(wire.getBytes(StandardCharsets.US_ASCII), 4, "JF");
        assertEquals("00", p.errorCode());
        assertEquals("8699636332605", p.fields().get("pinUnderLmk"));
    }
}
