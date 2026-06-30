package com.isc.sentinel.api.dto;

import lombok.Data;

/** Response for Luna encrypt/decrypt. */
@Data
public class LunaDataResponse {
    private String ciphertext;
    private String plaintext;
    private String iv;
    private String errCode;
    private String errText;
}
