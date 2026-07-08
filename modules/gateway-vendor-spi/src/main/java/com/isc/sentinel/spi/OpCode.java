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
    PIN_VERIFY,      // Thales DA/DB — Verify Terminal PIN (IBM 3624)
    PIN_TRANSLATE,   // Thales CA/CB — Translate PIN TPK→ZPK
    PIN_ENCRYPT,
    CVV_GEN,         // Thales CW/CX — Generate CVV/CVC/CVV2
    CVV_VERIFY,      // Thales CY/CZ — Verify CVV/CVC/CVV2
    ARQC_VERIFY,     // Thales KQ/KR — Verify ARQC / Generate ARPC
    MAC_GEN,             // Thales M6/M7 — Generate MAC
    MAC_VERIFY,          // Thales M8/M9 — Verify MAC
    KEY_GEN,
    KEY_TRANSLATE,
    HSM_STATUS,
    RANDOM_NUM,
    HASH_GEN,

    // PIN ops (Phase 2)
    PIN_GEN,                     // Thales JA/JB — Generate Random PIN under LMK
    PVV_GEN,                     // Thales DG/DH — Generate VISA PVV
    IBM_OFFSET_GEN,              // Thales DE/DF — Generate IBM PIN Offset
    PIN_VERIFY_VISA,             // Thales DC/DD — Verify Terminal PIN (VISA PVV)
    INTERCHANGE_PIN_VERIFY_IBM,  // Thales EA/EB — Verify Interchange PIN (IBM 3624)
    INTERCHANGE_PIN_VERIFY_VISA, // Thales EC/ED — Verify Interchange PIN (VISA PVV)
    PIN_TRANSLATE_ZPK,           // Thales CC/CD — Translate PIN ZPK→ZPK
    CLEAR_PIN_ENCRYPT,           // Thales BA/BB — Encrypt Clear PIN under ZPK
    PIN_DERIVE_IBM,              // Thales EE/EF — Derive PIN from IBM Offset
    PIN_TO_LMK,                  // Thales JC/JD or JE/JF — Translate PIN TPK/ZPK → LMK
    PIN_FROM_LMK,                // Thales JG/JH — Translate PIN LMK → ZPK (encrypted)

    // Key management (Phase 2)
    KEY_EXPORT_ZMK,              // Thales GC/GD — Export ZPK under ZMK
    KEY_COMPONENT_GEN,           // Thales A2/A3 — Generate key component (clear)
    KEY_FORM_COMPONENTS,         // Thales A4/A5 — Form key from XOR'd components
    KEY_CHECK_VALUE,             // Thales BU/BV — Generate key check value
    KEY_GEN_DEK,                 // Luna — generate a DEK in-HSM, wrapped under a ZMK

    // Diagnostics
    HSM_ECHO,                    // Thales B2/B3 — Echo / loopback
    ARQC_VERIFY_EMV4,            // Thales KW/KX — Verify ARQC / Generate ARPC (EMV 4.x)

    // Phase 3 — 3DS / EMV advanced
    DCVV_VERIFY,                 // Thales PM/PN — Verify Dynamic CVV/CVC (CVN17 dCVV)
    CSC_CALC,                    // Thales RY/RZ mode=3 — Calculate CSC1/CSC2/AEVV
    CSC_VERIFY,                  // Thales RY/RZ mode=4 — Verify CSC1/CSC2/AEVV
    HMAC_GEN,                    // Thales LQ/LR — Generate HMAC (SPA2 AAV)
    HMAC_VERIFY,                 // Thales LS/LT — Verify HMAC (SPA2 AAV verify)

    // New commands (Phase 3+)
    KEY_GEN_TPK,                 // Thales HC/HD — Generate TPK
    KEY_GEN_ZPK,                 // Thales IA/IB — Generate ZPK
    PIN_DECRYPT,                 // Thales NG/NH — Decrypt Encrypted PIN
    RANDOM_DATA,                 // Thales OA/OB — Generate Random Data
    PIN_TRANSLATE_ZPK2,          // Thales JS/JT — Translate PIN ZPK→ZPK (variant 2)
    MAC_VERIFY_ALT,              // Thales VA/VB — Verify MAC (full-format variant)
    NET_HEALTH,                  // Thales NC/ND — Network Connectivity Check

    // Legacy / specialised
    FORMATTING_DATA_LOAD,        // Thales PA/PB — Load Formatting Data to HSM
    FORMATTING_DATA_ADD,         // Thales PC/PD — Load Additional Formatting Data
    PIN_MAILER_PRINT,            // Thales PE/PF — Print PIN / Solicitation Data
    PIN_MIGRATE_LMK,             // Thales BG/BH — Translate PIN from Old LMK to New LMK
    DUKPT_PIN_TRANSLATE,         // Thales G0/G1 — Translate PIN DUKPT → ZPK / DUKPT
    DUKPT_PIN_VERIFY,            // Thales GO/GP — Verify PIN (DUKPT BDK + PVK)

    // Luna TR-31 / KBPK (X9.143 key-derivation binding, software codec)
    KBPK_GEN,                    // Generate a Key Block Protection Key (AES/3DES)
    TR31_WRAP,                   // Wrap a working key into a TR-31 key block under a KBPK
    TR31_UNWRAP,                 // Unwrap (and authenticate) a TR-31 key block under a KBPK
    DEK_WRAP_TEST                // TEST helper: wrap a clear DEK under a clear ZMK (produces dekBlob)
}
