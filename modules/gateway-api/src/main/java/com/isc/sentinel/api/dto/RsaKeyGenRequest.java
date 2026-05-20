package com.isc.sentinel.api.dto;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

@Data
public class RsaKeyGenRequest {
    @NotBlank
    private String label;

    @NotNull
    @Min(1024)
    private Integer modulusBits = 2048;

    /** "0"=signature only, "1"=encipherment only, "2"=both */
    private String keyType = "2";

    /** "0"=ASN.1 SubjectPublicKeyInfo, "1"=raw modulus|exponent */
    private String encoding = "0";

    /** Public exponent as hex (default 65537 = 010001). */
    private String publicExponentHex = "010001";

    private String usage = "WRAP,UNWRAP";

    private String ownerOrg;
}
