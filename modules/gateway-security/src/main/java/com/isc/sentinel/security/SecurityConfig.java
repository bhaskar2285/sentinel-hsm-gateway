package com.isc.sentinel.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.List;
import java.util.stream.Stream;

@Configuration
@EnableMethodSecurity
public class SecurityConfig {

    private static final List<String> ALL_OPS = List.of(
        "KEY_CREATE_RSA","KEY_CREATE_SYM","KEY_IMPORT","KEY_IMPORT_ZMK","KEY_EXPORT","KEY_READ","KEY_DELETE",
        "KEY_FORM_BLOCK",
        "CRYPTO_DECRYPT","CRYPTO_ENCRYPT","MAC_GEN","MAC_VRFY",
        "PIN_VRFY","PIN_XLATE","PIN_VERIFY","PIN_TRANSLATE",
        "CVV_GEN","CVV_VERIFY","ARQC_VERIFY",
        "PIN_GEN","PVV_GEN","IBM_OFFSET_GEN",
        "KEY_COMPONENT_GEN","KEY_FORM_COMPONENTS","KEY_CHECK_VALUE",
        "HSM_STATUS","HSM_ECHO","ARQC_VERIFY_EMV4",
        "DCVV_VERIFY","CSC_CALC","CSC_VERIFY","HMAC_GEN","HMAC_VERIFY",
        "ADMIN_AUDIT","ADMIN_RBAC","RAW_CMD"
    );

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http,
                                           JdbcTemplate jdbc,
                                           RbacAuthorityResolver authorities,
                                           @Value("${sentinel.security.dev-mode:false}") boolean devMode) throws Exception {
        http
            .csrf(AbstractHttpConfigurer::disable)
            .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        if (devMode) {
            // DEV: permit all, inject all OP_* authorities via anonymous user.
            // Auth is OFF — localhost only (enforced by DevModeGuard).
            http
                .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
                .anonymous(a -> a.authorities(
                    Stream.concat(
                        Stream.of("ROLE_ADMIN"),
                        ALL_OPS.stream().map(op -> "OP_" + op)
                    ).toArray(String[]::new)
                ));
        } else {
            // SECURED: authenticate the gateway's own opaque session tokens
            // (AuthService.login -> isc_sam_session) and load RBAC authorities.
            // No external OAuth issuer required.
            http
                .authorizeHttpRequests(auth -> auth
                    .requestMatchers("/actuator/health", "/actuator/info").permitAll()
                    .requestMatchers("/v3/api-docs/**", "/swagger-ui/**", "/swagger-ui.html").permitAll()
                    .requestMatchers("/api/v1/jwe/public-key").permitAll()
                    .requestMatchers("/api/v1/auth/login", "/api/v1/auth/logout").permitAll()
                    .anyRequest().authenticated()
                )
                // Unauthenticated (missing/expired/invalid token) -> 401 so the client
                // redirects to login. 403 is reserved for authenticated-but-forbidden.
                .exceptionHandling(e -> e.authenticationEntryPoint(
                    new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED)))
                .addFilterBefore(new SessionTokenAuthFilter(jdbc, authorities),
                                 UsernamePasswordAuthenticationFilter.class);
        }

        return http.build();
    }
}
