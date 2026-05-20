package com.isc.sentinel.keyblock;

public enum KeyBlockFormat {
    TR31_B,   // AES KBPK derivation (CMAC + AES key-wrap-like)
    TR31_D,   // 3DES-style legacy
    X9_143,   // ANSI X9.143
    RAW       // unwrapped (admin/debug only)
}
