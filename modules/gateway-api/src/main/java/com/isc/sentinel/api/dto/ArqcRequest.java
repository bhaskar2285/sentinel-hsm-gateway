package com.isc.sentinel.api.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class ArqcRequest {
    /** UUID of IMK-AC (Issuer Master Key for Application Cryptography) under LMK. */
    @NotBlank private String imkKeyId;

    /** "03"=EMV Visa (default), "05"=EMV Mastercard, "41"=CPA. */
    private String mode = "03";

    /** ATC — kept for backwards compat; not sent to HSM in new KQ format. */
    private String atc;

    /** ARQC from card, 16 hex chars (8 bytes). */
    @NotBlank private String arqc;

    /** Transaction data used to generate ARQC (hex, variable length). */
    @NotBlank private String transData;

    /** Authorization Response Code, 4 hex chars (2 bytes), e.g. "3030" for "00" approved. */
    @NotBlank private String arc;

    /** 12 rightmost PAN digits excluding check digit. */
    @NotBlank private String pan;

    /** PAN sequence number, 2 digits (default "00"). */
    private String panSeqNo = "00";
}
