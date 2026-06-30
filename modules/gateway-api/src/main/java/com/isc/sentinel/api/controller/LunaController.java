package com.isc.sentinel.api.controller;

import com.isc.sentinel.api.dto.LunaDataRequest;
import com.isc.sentinel.api.dto.LunaDataResponse;
import com.isc.sentinel.api.dto.LunaDekImportRequest;
import com.isc.sentinel.api.dto.LunaKeyResponse;
import com.isc.sentinel.api.dto.LunaZmkFormRequest;
import com.isc.sentinel.api.service.LunaCryptoService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Luna (PKCS#11) ZMK->DEK custodian ceremony + data crypto. Separate from the Thales
 * payShield endpoints under /api/v1/crypto.
 */
@RestController
@RequestMapping("/api/v1/luna")
@RequiredArgsConstructor
public class LunaController {

    private final LunaCryptoService luna;

    private static String userOf(Authentication auth) {
        return auth == null ? "anonymous" : auth.getName();
    }

    @PostMapping("/zmk/form")
    public LunaKeyResponse formZmk(@Valid @RequestBody LunaZmkFormRequest req,
                                   @RequestHeader(value = "X-Bank-Id", required = false) Long bankId,
                                   Authentication auth) {
        return luna.formZmk(req, userOf(auth), bankId);
    }

    @PostMapping("/dek/import")
    public LunaKeyResponse importDek(@Valid @RequestBody LunaDekImportRequest req,
                                     @RequestHeader(value = "X-Bank-Id", required = false) Long bankId,
                                     Authentication auth) {
        return luna.importDek(req, userOf(auth), bankId);
    }

    @PostMapping("/data/encrypt")
    public LunaDataResponse encrypt(@Valid @RequestBody LunaDataRequest req, Authentication auth) {
        return luna.encrypt(req, userOf(auth));
    }

    @PostMapping("/data/decrypt")
    public LunaDataResponse decrypt(@Valid @RequestBody LunaDataRequest req, Authentication auth) {
        return luna.decrypt(req, userOf(auth));
    }
}
