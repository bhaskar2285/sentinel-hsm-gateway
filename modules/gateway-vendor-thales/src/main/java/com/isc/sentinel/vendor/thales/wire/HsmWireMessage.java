package com.isc.sentinel.vendor.thales.wire;

import java.nio.charset.StandardCharsets;
import java.util.Objects;

/**
 * Typed envelope around a payShield 10K wire message.
 *
 * On-wire (native payShield 2-byte length prefix):
 *   [2B BE length] [Header (m B)] [CommandCode (2A)] [Body (n A)] [opt X'19 + trailer]
 */
public final class HsmWireMessage {

    private final HsmHeader header;
    private final String commandCode;
    private final byte[] body;
    private final byte[] trailer;

    public HsmWireMessage(HsmHeader header, String commandCode, byte[] body, byte[] trailer) {
        this.header = Objects.requireNonNull(header, "header");
        this.commandCode = Objects.requireNonNull(commandCode, "commandCode");
        if (commandCode.length() != 2) {
            throw new IllegalArgumentException("command code must be 2 ASCII chars: " + commandCode);
        }
        this.body = (body != null) ? body : new byte[0];
        this.trailer = trailer;
    }

    public HsmHeader header() { return header; }
    public String commandCode() { return commandCode; }
    public byte[] body() { return body; }
    public byte[] trailer() { return trailer; }
    public boolean hasTrailer() { return trailer != null && trailer.length > 0; }

    public byte[] toWireBytes() {
        byte[] headerBytes = header.bytes();
        byte[] codeBytes = commandCode.getBytes(StandardCharsets.US_ASCII);

        int payloadLen = headerBytes.length + codeBytes.length + body.length;
        if (hasTrailer()) payloadLen += 1 + trailer.length;
        if (payloadLen > 0xFFFF) throw new IllegalStateException("payload too large for 2-byte len: " + payloadLen);

        byte[] out = new byte[2 + payloadLen];
        out[0] = (byte) ((payloadLen >> 8) & 0xFF);
        out[1] = (byte) (payloadLen & 0xFF);

        int pos = 2;
        System.arraycopy(headerBytes, 0, out, pos, headerBytes.length); pos += headerBytes.length;
        System.arraycopy(codeBytes, 0, out, pos, codeBytes.length);     pos += codeBytes.length;
        System.arraycopy(body, 0, out, pos, body.length);               pos += body.length;
        if (hasTrailer()) {
            out[pos++] = 0x19;
            System.arraycopy(trailer, 0, out, pos, trailer.length);
        }
        return out;
    }
}
