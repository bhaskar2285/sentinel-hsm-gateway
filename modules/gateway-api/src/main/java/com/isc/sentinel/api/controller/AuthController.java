package com.isc.sentinel.api.controller;

import com.isc.sentinel.api.auth.AuthResult;
import com.isc.sentinel.api.auth.AuthService;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import jakarta.servlet.http.HttpServletRequest;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/login")
    public ResponseEntity<AuthResult> login(@RequestBody LoginRequest req, HttpServletRequest http) {
        String ip = http.getRemoteAddr();
        String ua = http.getHeader("User-Agent");
        AuthResult r = authService.login(req.getLoginname(), req.getPassword(), ip, ua);
        if (!r.isSuccess()) {
            return ResponseEntity.status(401).body(r);
        }
        return ResponseEntity.ok(r);
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(@RequestHeader(value = "X-Session-Token", required = false) String token) {
        if (token != null && !token.isEmpty()) authService.logout(token);
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/hash-password")
    public ResponseEntity<String> hash(@RequestBody LoginRequest req) {
        return ResponseEntity.ok(AuthService.hashDb(req.getLoginname(), req.getPassword()));
    }

    @Data
    public static class LoginRequest {
        private String loginname;
        private String password;
    }
}
