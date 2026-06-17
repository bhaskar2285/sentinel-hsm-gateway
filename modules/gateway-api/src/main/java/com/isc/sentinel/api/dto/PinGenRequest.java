package com.isc.sentinel.api.dto;

import lombok.Data;

@Data
public class PinGenRequest {
    /** Full PAN — rightmost 12 digits (excl. check digit) form the JA account number. */
    private String pan;

    /** PIN length, 4–12 digits (default "04"). */
    private String pinLen = "04";
}
