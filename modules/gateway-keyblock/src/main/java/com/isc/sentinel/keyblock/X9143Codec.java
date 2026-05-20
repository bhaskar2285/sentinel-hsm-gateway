package com.isc.sentinel.keyblock;

/**
 * ANSI X9.143 key block wrap/unwrap.
 *
 * Phase-1 placeholder: defers to Tr31Codec (Format D) which is a subset / aligned profile.
 * Full X9.143-2022 extensions (optional blocks: KS, KC, TS, DA, etc) tracked for Phase 2.
 */
public final class X9143Codec {

    private X9143Codec() {}

    public static String wrap(byte[] kbpk, byte[] keyToWrap, String usage2, char algo1, char mode1, char exportability) {
        // TODO Phase 2 — full X9.143 optional blocks (KS=key set, KC=KCV, TS=timestamp, DA=derivation algorithm)
        return Tr31Codec.wrap(kbpk, keyToWrap, usage2, algo1, mode1, exportability);
    }

    public static byte[] unwrap(byte[] kbpk, String keyBlock) {
        return Tr31Codec.unwrap(kbpk, keyBlock);
    }
}
