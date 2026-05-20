package com.isc.sentinel.vendor.thales.wire;

/**
 * Thales LMK / ZMK key scheme codes.
 *
 * Scheme byte precedes the encrypted key hex on the wire and tells the receiver
 * how many hex chars follow. payShield 10K Host Programmer's Manual, Key Scheme appendix.
 */
public enum KeyScheme {
    Z_SINGLE_DES   ('Z',  8,  16),    // single-length DES (legacy)
    U_DOUBLE_3DES  ('U', 16,  32),    // double-length 3DES — most common
    T_TRIPLE_3DES  ('T', 24,  48),    // triple-length 3DES
    X_DOUBLE_VAR   ('X', 16,  32),    // variant double-length
    Y_TRIPLE_VAR   ('Y', 24,  48),    // variant triple-length
    R_AES_128      ('R', 16,  32),    // AES-128 (key block)
    S_AES_192      ('S', 24,  48),    // AES-192
    H_AES_256      ('H', 32,  64);    // AES-256

    private final char code;
    private final int byteLen;
    private final int hexLen;

    KeyScheme(char code, int byteLen, int hexLen) {
        this.code    = code;
        this.byteLen = byteLen;
        this.hexLen  = hexLen;
    }

    public char  code()    { return code; }
    public int   byteLen() { return byteLen; }
    public int   hexLen()  { return hexLen; }

    public static KeyScheme of(char code) {
        for (KeyScheme s : values()) if (s.code == code) return s;
        throw new IllegalArgumentException("unknown key scheme: '" + code + "'");
    }

    /** Hex chars expected after the scheme byte. */
    public static int hexLenForScheme(char code) {
        return of(code).hexLen;
    }
}
