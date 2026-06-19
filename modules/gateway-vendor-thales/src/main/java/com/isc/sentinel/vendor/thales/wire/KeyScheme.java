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

    /**
     * True for the variable-length LMK key-block scheme tags.
     *
     * On a Key Block LMK the encrypted key on the wire is NOT a fixed-length hex
     * string — it is a self-describing block: {@code <scheme><version><LLLL><header...><data><mac>}
     * where {@code LLLL} (4 decimal digits) is the total block length that follows the
     * scheme tag. Real payShield traffic uses tag 'S' (3DES key block) and 'R'
     * (the imported TR-31 'R'/AES block). Confirmed against live TTB wire captures:
     *   S0007271TN00S0001...  -> LLLL=0072 -> 72 chars after 'S'
     *   RB0080P0TB00E0000...  -> LLLL=0080 -> 80 chars after 'R'
     */
    public static boolean isKeyBlockScheme(char code) {
        return code == 'S' || code == 'R';
    }

    /**
     * Number of characters the key token occupies AFTER the scheme byte, read from
     * the wire at {@code schemePos} (the index of the scheme char in {@code wire}).
     *
     * For fixed schemes (Z/U/T/X/Y) this is the static hex length. For key-block
     * schemes (S/R) it is the embedded 4-digit decimal length at {@code wire[schemePos+2..schemePos+6]}.
     */
    public static int keyTokenLen(String wire, int schemePos) {
        char code = wire.charAt(schemePos);
        if (isKeyBlockScheme(code)) {
            return Integer.parseInt(wire.substring(schemePos + 2, schemePos + 6));
        }
        return hexLenForScheme(code);
    }
}
