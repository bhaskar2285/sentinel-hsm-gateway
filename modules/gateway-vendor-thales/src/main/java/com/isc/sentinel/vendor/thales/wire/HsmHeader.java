package com.isc.sentinel.vendor.thales.wire;

import java.nio.charset.StandardCharsets;
import java.util.Objects;

/**
 * Thales payShield 10K message header.
 * Echoed unchanged by HSM in response → host correlates async req/resp.
 * Length m is per-tenant config (typically 4).
 */
public final class HsmHeader {

    public static final int DEFAULT_LENGTH = 4;
    public static final String DEFAULT_TEXT = "SENT";
    public static final HsmHeader DEFAULT = new HsmHeader(DEFAULT_TEXT);

    private final String text;

    public HsmHeader(String text) {
        Objects.requireNonNull(text, "header text");
        if (text.isEmpty() || text.length() > 16) {
            throw new IllegalArgumentException("header length must be 1..16: " + text);
        }
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c < 0x20 || c > 0x7E) {
                throw new IllegalArgumentException("header must be printable ASCII: " + text);
            }
        }
        this.text = text;
    }

    public String text()   { return text; }
    public int length()    { return text.length(); }
    public byte[] bytes()  { return text.getBytes(StandardCharsets.US_ASCII); }

    @Override public boolean equals(Object o) { return (o instanceof HsmHeader h) && h.text.equals(text); }
    @Override public int hashCode() { return text.hashCode(); }
    @Override public String toString() { return "HsmHeader[" + text + "]"; }
}
