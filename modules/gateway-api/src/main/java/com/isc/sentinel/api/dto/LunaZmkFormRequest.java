package com.isc.sentinel.api.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import lombok.Data;

import java.util.List;

/** Luna ceremony: form a ZMK token object from the XOR of clear custodian components. */
@Data
public class LunaZmkFormRequest {
    /** Clear ZMK components (equal-length hex), min 2. XOR'd into the ZMK. */
    @NotEmpty
    private List<String> components;

    /** JCA key algorithm of the ZMK (default 3DES). */
    private String algorithm = "DESede";

    /** Vault label / Luna partition object label for the ZMK. */
    @NotBlank
    private String label;
}
