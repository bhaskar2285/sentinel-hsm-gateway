package com.isc.sentinel.api.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class PinTranslateZpkRequest {
    /** UUID of source ZPK under LMK. */
    @NotBlank private String srcZpkKeyId;

    /** UUID of destination ZPK under LMK. */
    @NotBlank private String dstZpkKeyId;

    /** PIN block encrypted under source ZPK, 16 hex chars. */
    @NotBlank private String pinBlock;

    /** PIN block format, 2 digits (default "01"). */
    private String pinBlockFormat = "01";

    /** Full PAN (rightmost 12 excl check digit extracted automatically). */
    @NotBlank private String pan;

    /** Destination block format flag (default same as pinBlockFormat). */
    private String dstFlag = "01";

    /** Source block format flag (default same as pinBlockFormat). */
    private String srcFlag = "01";
}
