package com.isc.sentinel.api.jwe;

import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Base64;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/jwe")
@RequiredArgsConstructor
public class JwePublicKeyController {

    private final JweKeyHolder keyHolder;

    @GetMapping("/public-key")
    public Map<String, String> publicKey() {
        byte[] encoded = keyHolder.publicKey().getEncoded();
        return Map.of(
            "algorithm", "RSA-OAEP-256",
            "encryption", "A256GCM",
            "encoding", "X509-SubjectPublicKeyInfo-Base64",
            "publicKey", Base64.getEncoder().encodeToString(encoded)
        );
    }
}
