package com.isc.sentinel.api.controller;

import com.isc.sentinel.api.dto.LunaDataRequest;
import com.isc.sentinel.api.dto.LunaDataResponse;
import com.isc.sentinel.api.dto.LunaDekImportRequest;
import com.isc.sentinel.api.dto.LunaDekWrapTestRequest;
import com.isc.sentinel.api.dto.LunaDekWrapTestResponse;
import com.isc.sentinel.api.dto.LunaExportRequest;
import com.isc.sentinel.api.dto.LunaKbpkRequest;
import com.isc.sentinel.api.dto.LunaKcvRequest;
import com.isc.sentinel.api.dto.LunaKeyResponse;
import com.isc.sentinel.api.dto.LunaTr31BlockSummary;
import com.isc.sentinel.api.dto.LunaTr31Response;
import com.isc.sentinel.api.dto.LunaTr31UnwrapRequest;
import com.isc.sentinel.api.dto.LunaTr31WrapRequest;
import com.isc.sentinel.api.dto.LunaZmkFormRequest;
import com.isc.sentinel.api.service.LunaCryptoService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

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

    /** TEST helper — build a dekBlob (clear DEK wrapped under a clear ZMK) for /dek/import. */
    @PostMapping("/dek/wrap-test")
    public LunaDekWrapTestResponse dekWrapTest(@Valid @RequestBody LunaDekWrapTestRequest req,
                                               Authentication auth) {
        return luna.dekWrapTest(req, userOf(auth));
    }

    @PostMapping("/data/encrypt")
    public LunaDataResponse encrypt(@Valid @RequestBody LunaDataRequest req, Authentication auth) {
        return luna.encrypt(req, userOf(auth));
    }

    @PostMapping("/data/decrypt")
    public LunaDataResponse decrypt(@Valid @RequestBody LunaDataRequest req, Authentication auth) {
        return luna.decrypt(req, userOf(auth));
    }

    // ---- TR-31 / KBPK -------------------------------------------------------

    @PostMapping("/kbpk/generate")
    public LunaKeyResponse generateKbpk(@Valid @RequestBody LunaKbpkRequest req,
                                        @RequestHeader(value = "X-Bank-Id", required = false) Long bankId,
                                        Authentication auth) {
        return luna.generateKbpk(req, userOf(auth), bankId);
    }

    @PostMapping("/tr31/wrap")
    public LunaTr31Response tr31Wrap(@Valid @RequestBody LunaTr31WrapRequest req,
                                     @RequestHeader(value = "X-Bank-Id", required = false) Long bankId,
                                     Authentication auth) {
        return luna.tr31Wrap(req, userOf(auth), bankId);
    }

    @PostMapping("/tr31/unwrap")
    public LunaTr31Response tr31Unwrap(@Valid @RequestBody LunaTr31UnwrapRequest req, Authentication auth) {
        return luna.tr31Unwrap(req, userOf(auth));
    }

    @GetMapping("/tr31/blocks")
    public List<LunaTr31BlockSummary> listTr31Blocks() {
        return luna.listTr31Blocks();
    }

    @PostMapping("/kcv")
    public LunaKeyResponse kcv(@Valid @RequestBody LunaKcvRequest req, Authentication auth) {
        return luna.computeKcv(req, userOf(auth));
    }

    @PostMapping("/export")
    public LunaTr31Response export(@Valid @RequestBody LunaExportRequest req,
                                   @RequestHeader(value = "X-Bank-Id", required = false) Long bankId,
                                   Authentication auth) {
        return luna.exportLunaKey(req, userOf(auth), bankId);
    }
}
