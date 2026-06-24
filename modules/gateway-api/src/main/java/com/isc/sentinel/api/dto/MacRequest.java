package com.isc.sentinel.api.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class MacRequest {
    /** UUID of MAC key under LMK. */
    @NotBlank private String keyId;

    /** MAC mode: 0=ECB, 1=CBC-final, 2=CBC-initial, 3=CBC-intermediate (default "0"). */
    private String mode = "0";

    /** Input format: 0=binary, 1=ASCII, 2=EBCDIC (default "0"). */
    private String inputFormat = "0";

    /** MAC Algorithm (1N): "1"=ISO 9797 alg 1 (X9.9, DES), "3"=ISO 9797 alg 3 (X9.19, 3DES, default),
     *  "5"=CBC-MAC (AES), "6"=CMAC (AES). Single digit — the wire field is 1N. */
    private String algorithm = "3";

    /** Padding method: 0=none, 1=ANSI X9.19, 2=ISO 16609 (default "1"). */
    private String padding = "1";

    /** Data to MAC, hex-encoded. */
    @NotBlank private String dataHex;

    /** IV for CBC modes, 16 hex chars (default zeros). */
    private String iv = "0000000000000000";
}
