package com.isc.sentinel.spi;

/**
 * Gateway-level operation codes. Vendor-neutral.
 * Each adapter maps OpCode → vendor wire command (e.g., Thales 2-letter codes).
 */
public enum OpCode {
    // Phase 1
    RSA_KEY_GEN,            // Thales EI/EJ
    KEY_IMPORT_RSA_WRAPPED, // Thales GI/GJ
    KEY_EXPORT,             // Thales A8/A9 (legacy ZMK-wrap)
    KEY_FORM_BLOCK,         // Thales B0/B1 (TR-31 / X9.143 key block wrap)
    KEY_IMPORT_ZMK,         // Thales A6/A7 (import symmetric key under ZMK)
    DATA_DECRYPT,           // Thales M2/M3

    // Phase 2 (populated incrementally)
    DATA_ENCRYPT,
    PIN_VERIFY,
    PIN_TRANSLATE,
    PIN_ENCRYPT,
    MAC_GEN,
    MAC_VERIFY,
    KEY_GEN,
    KEY_TRANSLATE,
    HSM_STATUS,
    RANDOM_NUM,
    HASH_GEN
}
