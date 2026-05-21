package com.isc.sentinel.api.controller;

import com.isc.sentinel.api.dto.DecryptRequest;
import com.isc.sentinel.api.dto.DecryptResponse;
import com.isc.sentinel.api.dto.EncryptRequest;
import com.isc.sentinel.api.dto.EncryptResponse;
import com.isc.sentinel.api.service.CryptoService;
import com.isc.sentinel.api.service.KeyService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/crypto")
@RequiredArgsConstructor
public class CryptoController {

    private final CryptoService cryptoService;
    private final KeyService    keyService;

    private static String userOf(Authentication auth) {
        return auth == null ? "anonymous" : auth.getName();
    }

    @PostMapping("/decrypt")
    @PreAuthorize("hasAuthority('OP_CRYPTO_DECRYPT')")
    public DecryptResponse decrypt(@Valid @RequestBody DecryptRequest req, Authentication auth) {
        return cryptoService.decrypt(req, userOf(auth));
    }

    @PostMapping("/encrypt")
    @PreAuthorize("hasAuthority('OP_CRYPTO_ENCRYPT')")
    public EncryptResponse encrypt(@Valid @RequestBody EncryptRequest req, Authentication auth) {
        return keyService.encrypt(req, userOf(auth));
    }
}
