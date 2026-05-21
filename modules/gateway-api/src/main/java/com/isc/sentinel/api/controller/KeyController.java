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

    /** Tenant context derived from request headers set by the console after login. */
    private static TenantCtx tenantOf(Long bankId, Long branchId) {
        return new TenantCtx(bankId, branchId);
    }

    public record TenantCtx(Long bankRecId, Long branchRecId) {}

    @PostMapping("/rsa")
    @PreAuthorize("hasAuthority('OP_KEY_CREATE_RSA')")
    public RsaKeyGenResponse generateRsa(@Valid @RequestBody RsaKeyGenRequest req,
                                         Authentication auth,
                                         @RequestHeader(value = "X-Bank-Id",   required = false) Long bankId,
                                         @RequestHeader(value = "X-Branch-Id", required = false) Long branchId) {
        return keyService.generateRsa(req, userOf(auth), tenantOf(bankId, branchId));
    }

    @PostMapping("/symmetric")
    @PreAuthorize("hasAuthority('OP_KEY_CREATE_SYM')")
    public SymKeyGenResponse generateSymmetric(@Valid @RequestBody SymKeyGenRequest req,
                                               Authentication auth,
                                               @RequestHeader(value = "X-Bank-Id",   required = false) Long bankId,
                                               @RequestHeader(value = "X-Branch-Id", required = false) Long branchId) {
        return keyService.generateSymmetric(req, userOf(auth), tenantOf(bankId, branchId));
    }

    @PostMapping("/import-rsa-wrapped")
    @PreAuthorize("hasAuthority('OP_KEY_IMPORT')")
    public KeyImportResponse importRsaWrapped(@Valid @RequestBody ImportRsaWrappedRequest req,
                                              Authentication auth,
                                              @RequestHeader(value = "X-Bank-Id",   required = false) Long bankId,
                                              @RequestHeader(value = "X-Branch-Id", required = false) Long branchId) {
        return keyService.importRsaWrapped(req, userOf(auth), tenantOf(bankId, branchId));
    }

    @PostMapping("/import-zmk-wrapped")
    @PreAuthorize("hasAuthority('OP_KEY_IMPORT_ZMK')")
    public KeyImportResponse importZmkWrapped(@Valid @RequestBody ImportZmkWrappedRequest req,
                                              Authentication auth,
                                              @RequestHeader(value = "X-Bank-Id",   required = false) Long bankId,
                                              @RequestHeader(value = "X-Branch-Id", required = false) Long branchId) {
        return keyService.importZmkWrapped(req, userOf(auth), tenantOf(bankId, branchId));
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
                                         @RequestParam(required = false) String keyType,
                                         @RequestHeader(value = "X-Bank-Id", required = false) Long bankId) {
        return keyService.list(label, keyType, bankId);
    }

    @GetMapping("/{keyId}")
    @PreAuthorize("hasAuthority('OP_KEY_READ')")
    public KeyDetailResponse get(@PathVariable String keyId) {
        return keyService.get(keyId);
    }
}
