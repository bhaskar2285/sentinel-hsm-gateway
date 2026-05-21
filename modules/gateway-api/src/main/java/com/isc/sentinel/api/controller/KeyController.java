package com.isc.sentinel.api.controller;

import com.isc.sentinel.api.dto.*;
import com.isc.sentinel.api.service.KeyService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/v1/keys")
@RequiredArgsConstructor
public class KeyController {

    private final KeyService keyService;

    private static String userOf(Authentication auth) {
        return auth == null ? "anonymous" : auth.getName();
    }

    @PostMapping("/rsa")
    @PreAuthorize("hasAuthority('OP_KEY_CREATE_RSA')")
    public RsaKeyGenResponse generateRsa(@Valid @RequestBody RsaKeyGenRequest req, Authentication auth) {
        return keyService.generateRsa(req, userOf(auth));
    }

    @PostMapping("/symmetric")
    @PreAuthorize("hasAuthority('OP_KEY_CREATE_SYM')")
    public SymKeyGenResponse generateSymmetric(@Valid @RequestBody SymKeyGenRequest req, Authentication auth) {
        return keyService.generateSymmetric(req, userOf(auth));
    }

    @PostMapping("/import-rsa-wrapped")
    @PreAuthorize("hasAuthority('OP_KEY_IMPORT')")
    public KeyImportResponse importRsaWrapped(@Valid @RequestBody ImportRsaWrappedRequest req, Authentication auth) {
        return keyService.importRsaWrapped(req, userOf(auth));
    }

    @PostMapping("/import-zmk-wrapped")
    @PreAuthorize("hasAuthority('OP_KEY_IMPORT_ZMK')")
    public KeyImportResponse importZmkWrapped(@Valid @RequestBody ImportZmkWrappedRequest req, Authentication auth) {
        return keyService.importZmkWrapped(req, userOf(auth));
    }

    @PostMapping("/{keyId}/export")
    @PreAuthorize("hasAuthority('OP_KEY_EXPORT')")
    public ExportKeyResponse exportKey(@PathVariable String keyId,
                                       @Valid @RequestBody ExportKeyRequest req,
                                       Authentication auth) {
        return keyService.exportKey(keyId, req, userOf(auth));
    }

    @GetMapping
    @PreAuthorize("hasAuthority('OP_KEY_READ')")
    public List<KeySummaryResponse> list(@RequestParam(required = false) String label,
                                         @RequestParam(required = false) String keyType) {
        return keyService.list(label, keyType);
    }

    @GetMapping("/{keyId}")
    @PreAuthorize("hasAuthority('OP_KEY_READ')")
    public KeyDetailResponse get(@PathVariable String keyId) {
        return keyService.get(keyId);
    }
}
