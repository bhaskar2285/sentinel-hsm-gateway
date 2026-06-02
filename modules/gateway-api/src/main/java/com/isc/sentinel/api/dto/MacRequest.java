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

    /** Algorithm: "01"=DES X9.9 (8-byte key), "03"=3DES X9.19 (16-byte key, default). */
    private String algorithm = "03";

    /** Padding method: 0=none, 1=ANSI X9.19, 2=ISO 16609 (default "1"). */
    private String padding = "1";

    /** Data to MAC, hex-encoded. */
    @NotBlank private String dataHex;

    /** IV for CBC modes, 16 hex chars (default zeros). */
    private String iv = "0000000000000000";
}
