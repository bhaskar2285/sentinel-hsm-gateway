package com.isc.sentinel.api.dto;

import lombok.Data;

@Data
public class ExportKeyRequest {
    /** "TR31_B" | "TR31_D" | "X9_143" | "RAW" */
    private String format = "TR31_D";

    /** KBPK (Key Block Protection Key) UUID — AES recommended for TR-31 D. */
    private String kbpkKeyId;

    /** "0"=ZMK, "1"=TMK (Thales A8 flag) */
    private String kekType = "0";

    private String schemeZmk = "U";
    private String schemeLmk = "U";

    private Integer keyType = 0;

    /** TR-31 / X9.143 header attributes (used only for TR31_B/TR31_D/X9_143). */
    private String usage2  = "K0";   // 2-char key usage: K0=Key Encryption Key, P0=PIN-Encryption, M0=MAC etc.
    private String algo1   = "T";    // 1-char algorithm of wrapped key: T=3DES, A=AES, D=DES, R=RSA, H=HMAC
    private String mode1   = "E";    // 1-char mode: E=encrypt, D=decrypt, B=both, N=none, V=verify, X=key-deriv, C=MAC
    private String export1 = "E";    // 1-char exportability: E=trusted-export, N=non-exportable, S=sensitive
}
