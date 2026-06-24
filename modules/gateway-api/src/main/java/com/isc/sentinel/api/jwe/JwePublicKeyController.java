package com.isc.sentinel.api.jwe;

import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.MessageDigest;
import java.util.Base64;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/jwe")
@RequiredArgsConstructor
public class JwePublicKeyController {

    private final JweKeyHolder keyHolder;

    @GetMapping("/public-key")
    public Map<String, String> publicKey() throws Exception {
        byte[] encoded = keyHolder.publicKey().getEncoded();
        return Map.of(
            "algorithm", "RSA-OAEP-256",
            "encryption", "A256GCM",
            "encoding", "X509-SubjectPublicKeyInfo-Base64",
            "publicKey", Base64.getEncoder().encodeToString(encoded),
            // SHA-256 fingerprint of the SPKI — pin this out-of-band to detect MITM swaps.
            "sha256", Base64.getEncoder().encodeToString(
                MessageDigest.getInstance("SHA-256").digest(encoded))
        );
    }

    /** Deliberate JWE key rotation. Invalidates in-flight JWE blobs; redistribute the new key OOB. */
    @PostMapping("/rotate")
    @PreAuthorize("hasRole('ADMIN')")
    public Map<String, String> rotate() throws Exception {
        keyHolder.rotate();
        return publicKey();
    }
}
