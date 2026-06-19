package com.isc.sentinel.vendor.thales.command;

import com.isc.sentinel.vendor.thales.wire.HsmHeader;
import com.isc.sentinel.vendor.thales.wire.HsmWireMessage;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.HexFormat;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Locks the M0/M2 (Encrypt/Decrypt Data Block) wire format against the live payShield +
 * TTB trace behaviour: Message Length is 4 HEX digits = BYTE count (not %04d decimal), and
 * with Input Format '0' the Message is RAW BINARY (not hex text). Output Format '1' => hex
 * M1/M3 response (string-parseable, MsgLen = hex-char count).
 */
class M0EncryptWireTest {

    private static final HsmHeader HDR = new HsmHeader("RSM5");

    @Test
    void buildM0EmitsHexByteLengthAndBinaryData() {
        String keyHex = "U0123456789ABCDEF0123456789ABCDEF"; // scheme U + 32H (double-length 3DES)
        String plain  = "00112233445566778899AABBCCDDEEFF";   // 16 bytes -> X'0010

        HsmWireMessage m = ThalesCmdBuilder.buildM0(HDR, Map.of("keyHex", keyHex, "plaintextHex", plain));
        byte[] body = m.body();
        String head = new String(body, 0, body.length - 16, StandardCharsets.US_ASCII);

        // body() excludes the "M0" command code: mode(00) + inFmt(0) + outFmt(1) + keyType(00A) + key + msgLen
        assertEquals("00" + "0" + "1" + "00A" + keyHex + "0010", head);
        // trailing 16 bytes are the RAW plaintext, not 32 hex chars
        byte[] tail = new byte[16];
        System.arraycopy(body, body.length - 16, tail, 0, 16);
        assertArrayEquals(HexFormat.of().parseHex(plain), tail);
    }

    @Test
    void parseM1ReadsHexCharCountLength() {
        // M1 response: header + M1 + err(00) + msgLen(0020 hex = 32 chars) + 32-char hex ciphertext
        String cipher = "42DC174ADD60C73199B7FC7392F491EF"; // 32 hex chars (16 bytes)
        String wire   = "RSM5" + "M1" + "00" + "0020" + cipher;
        ThalesCmdParser.Parsed p =
            ThalesCmdParser.parse(wire.getBytes(StandardCharsets.US_ASCII), 4, "M1");
        assertEquals("00", p.errorCode());
        assertEquals(cipher, p.fields().get("ciphertext"));
        assertEquals(16, p.fields().get("messageLength"));
    }
}
