package com.isc.sentinel.api.controller;

import com.isc.sentinel.api.dto.DecryptRequest;
import com.isc.sentinel.api.dto.DecryptResponse;
import com.isc.sentinel.api.service.CryptoService;
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

    @PostMapping("/decrypt")
    @PreAuthorize("hasAuthority('OP_CRYPTO_DECRYPT')")
    public DecryptResponse decrypt(@Valid @RequestBody DecryptRequest req, Authentication auth) {
        String user = auth == null ? "anonymous" : auth.getName();
        return cryptoService.decrypt(req, user);
    }
}
