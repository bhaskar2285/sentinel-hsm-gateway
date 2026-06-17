package com.isc.sentinel.api.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class ClearPinEncryptRequest {
    /** Clear PIN digits (4–12). */
    @NotBlank private String clearPin;

    /** Full PAN — rightmost 12 digits (excl. check digit) form the account number. */
    @NotBlank private String pan;

    /**
     * Max PIN length L (HSM "PIN field length" CS setting, range 5–13). This
     * deployment's HSM uses 13. The clear PIN is left-justified and 'F'-padded
     * to this length on the wire.
     */
    private String maxPinLen = "13";
}
