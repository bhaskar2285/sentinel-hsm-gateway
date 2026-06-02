package com.isc.sentinel.api.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class ExportZmkRequest {
    /** UUID of ZMK under LMK (wrapping key). */
    @NotBlank private String zmkKeyId;

    /** UUID of ZPK under LMK (key to export). */
    @NotBlank private String zpkKeyId;
}
