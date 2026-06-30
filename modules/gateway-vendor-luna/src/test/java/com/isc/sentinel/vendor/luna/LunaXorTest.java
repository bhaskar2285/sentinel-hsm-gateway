package com.isc.sentinel.vendor.luna;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class LunaXorTest {

    @Test
    void xorsThreeComponents() {
        byte[] r = LunaVendorAdapter.xorHex(List.of(
            "0000000000000000FFFFFFFFFFFFFFFF",
            "FFFFFFFFFFFFFFFF0000000000000000",
            "0123456789ABCDEF0123456789ABCDEF"));
        // 00^FF^01 = FE ... per byte; FF^00^01 = FE ...
        assertEquals("FEDCBA9876543210FEDCBA9876543210", LunaVendorAdapter.hexUpper(r));
    }

    @Test
    void xorOfTwoEqualComponentsIsZero() {
        byte[] r = LunaVendorAdapter.xorHex(List.of(
            "0123456789ABCDEF", "0123456789ABCDEF"));
        assertEquals("0000000000000000", LunaVendorAdapter.hexUpper(r));
    }

    @Test
    void rejectsMismatchedLengths() {
        assertThrows(IllegalArgumentException.class, () ->
            LunaVendorAdapter.xorHex(List.of("0011", "001122")));
    }
}
