package com.isc.sentinel.api.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class PinTranslateRequest {
    /** UUID of the source TPK (Terminal PIN Key) stored under LMK. */
    @NotBlank private String tpkKeyId;

    /** UUID of the destination ZPK/BDK stored under LMK. */
    @NotBlank private String zpkKeyId;

    /** PIN block from terminal, 16 hex chars. */
    @NotBlank private String pinBlock;

    /** "01"=ISO 9564-1 format 0 (default). */
    private String pinBlockFormat = "01";

    /** 12 rightmost PAN digits excluding check digit. */
    @NotBlank private String pan;

    /** Max PIN length hint for HSM (default "12"). */
    private String maxPinLen = "12";
}
