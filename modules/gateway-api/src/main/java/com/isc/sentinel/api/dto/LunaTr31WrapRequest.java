package com.isc.sentinel.api.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

/** Wrap a clear working key into a TR-31 key block under a stored KBPK. */
@Data
public class LunaTr31WrapRequest {
    /** keyUuid of the KBPK formed by /luna/kbpk/generate. */
    @NotBlank
    private String kbpkKeyId;

    /** Clear working key to protect (hex). */
    @NotBlank
    private String workingKeyHex;

    /** Working key's own algorithm ("AES" or "DESede") — sets the TR-31 header algorithm field. */
    private String keyAlgorithm = "AES";

    /** Optional vault label to persist the produced key block under (auto-generated if omitted). */
    private String label;

    /** TR-31 header key usage (2 chars, e.g. D0 = data, P0 = PIN, K0 = key). */
    private String keyUsage = "D0";

    /** TR-31 mode of use (1 char: B = enc+dec, E = encrypt, D = decrypt, N = none). */
    private String modeOfUse = "B";

    /** TR-31 exportability (1 char: E = exportable, S = sensitive, N = non-exportable). */
    private String exportability = "E";
}
