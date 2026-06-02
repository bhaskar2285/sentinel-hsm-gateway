package com.isc.sentinel.api.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class PinVerifyRequest {
    /** UUID of TPK (Terminal PIN Key) under LMK. */
    @NotBlank private String tpkKeyId;

    /** UUID of PVK (PIN Verification Key) under LMK. */
    @NotBlank private String pvkKeyId;

    /** PIN block from terminal, 16 hex chars. */
    @NotBlank private String pinBlock;

    /** "01"=ISO 9564-1 format 0 (default). */
    private String pinBlockFormat = "01";

    /** 12 rightmost PAN digits excluding check digit. */
    @NotBlank private String pan;

    /** IBM 3624: "0"=format check only, "4"=verify 4-digit offset (default "0"). */
    private String checkLen = "0";

    /** IBM 3624 decimalization table, 16 hex chars (required when checkLen > 0). */
    private String dectab;

    /** IBM 3624 PIN offset, checkLen hex chars (required when checkLen > 0). */
    private String pinOffset;
}
