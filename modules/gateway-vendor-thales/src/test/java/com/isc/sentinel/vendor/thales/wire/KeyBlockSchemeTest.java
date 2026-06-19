package com.isc.sentinel.vendor.thales.wire;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Locks the variable-length Key Block scheme handling against REAL payShield wire
 * captured from the TTB IST-Switch <-> payShield 10K trace (header RSM5).
 *
 * On a Key Block LMK the encrypted key is self-describing: after the scheme tag the
 * 4 decimal digits at offset +2 give the total block length. These exact tokens were
 * lifted from the live trace (TTB KEyblock audits.txt):
 *   CA  TPK : S0007271TN00S0001 + 56 hex  -> 0072 -> 72 chars after 'S'
 *   CA  ZPK : S0007272TN00S0001 + 56 hex  -> 0072 -> 72 chars after 'S'
 *   CY  CVK : S00072C0TN00N0001 + 56 hex  -> 0072
 *   DA  PVK : S00072V1TN00N0001 + 56 hex  -> 0072
 *   A6 import block (TR-31 'R') : R B0080 P0TB00E0000 + 64 hex -> 0080 -> 80 after 'R'
 */
class KeyBlockSchemeTest {

    private static final String TPK =
        "S0007271TN00S00014C794C150ACECB13D66E37F373C6248A85B6178A31AE654965B80172";
    private static final String ZPK =
        "S0007272TN00S000184546BA28F7BF35C03460D0C567010D26484D5AC4671F87E86F674BA";
    private static final String RBLOCK =
        "RB0080P0TB00E0000647EBFDCF36E61A96790C7AF62F3B23DEB1B06A9A7532FCF892CF51415C45299";

    @Test
    void keyBlockSchemesAreSelfDescribing() {
        assertTrue(KeyScheme.isKeyBlockScheme('S'));
        assertTrue(KeyScheme.isKeyBlockScheme('R'));
        assertFalse(KeyScheme.isKeyBlockScheme('U'));
    }

    @Test
    void keyTokenLenReadsEmbeddedLengthForKeyBlock() {
        // 72 chars follow the 'S' tag (16-char header + 56 key/MAC hex)
        assertEquals(72, KeyScheme.keyTokenLen(TPK, 0));
        assertEquals(72, KeyScheme.keyTokenLen(ZPK, 0));
        assertEquals(TPK.length() - 1, KeyScheme.keyTokenLen(TPK, 0));
        // 80 chars follow the 'R' tag
        assertEquals(80, KeyScheme.keyTokenLen(RBLOCK, 0));
        assertEquals(RBLOCK.length() - 1, KeyScheme.keyTokenLen(RBLOCK, 0));
    }

    @Test
    void keyTokenLenKeepsFixedLengthForVariantSchemes() {
        // 'U' double-length 3DES is still a fixed 32 hex regardless of wire content
        String u = "U" + "0123456789ABCDEF0123456789ABCDEF" + "trailing";
        assertEquals(32, KeyScheme.keyTokenLen(u, 0));
    }

    @Test
    void twoAdjacentKeyBlocksSplitCleanly() {
        // mirrors the head of a real CA request: TPK block immediately followed by ZPK block
        String wire = TPK + ZPK;
        int p = 0;
        int l1 = KeyScheme.keyTokenLen(wire, p);
        String first = wire.substring(p, p + 1 + l1);
        p += 1 + l1;
        int l2 = KeyScheme.keyTokenLen(wire, p);
        String second = wire.substring(p, p + 1 + l2);
        assertEquals(TPK, first);
        assertEquals(ZPK, second);
    }
}
