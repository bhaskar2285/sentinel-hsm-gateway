package com.isc.sentinel.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;

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
                                           RbacJwtConverter rbacConverter,
                                           @Value("${sentinel.security.dev-mode:false}") boolean devMode) throws Exception {
        http
            .csrf(AbstractHttpConfigurer::disable)
            .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        if (devMode) {
            // DEV: permit all, inject all OP_* authorities via anonymous user
            http
                .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
                .anonymous(a -> a.authorities(
                    Stream.concat(
                        Stream.of("ROLE_ADMIN"),
                        ALL_OPS.stream().map(op -> "OP_" + op)
                    ).toArray(String[]::new)
                ));
        } else {
            JwtAuthenticationConverter jwtConverter = new JwtAuthenticationConverter();
            jwtConverter.setJwtGrantedAuthoritiesConverter(rbacConverter);

            http
                .authorizeHttpRequests(auth -> auth
                    .requestMatchers("/actuator/health", "/actuator/info").permitAll()
                    .requestMatchers("/v3/api-docs/**", "/swagger-ui/**", "/swagger-ui.html").permitAll()
                    .requestMatchers("/api/v1/jwe/public-key").permitAll()
                    .anyRequest().authenticated()
                )
                .oauth2ResourceServer(oauth -> oauth.jwt(jwt -> jwt.jwtAuthenticationConverter(jwtConverter)));
        }

        return http.build();
    }
}
