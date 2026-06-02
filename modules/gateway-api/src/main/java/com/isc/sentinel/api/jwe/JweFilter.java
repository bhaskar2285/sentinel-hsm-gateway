package com.isc.sentinel.api.jwe;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Component
@RequiredArgsConstructor
public class JweFilter extends OncePerRequestFilter {

    private static final String HEADER_JWE_FLAG = "X-JWE";
    private static final String HEADER_CLIENT_PUBLIC_KEY = "X-Client-Public-Key";
    private static final String CONTENT_TYPE_JOSE = "application/jose+json";
    private static final String CONTENT_TYPE_JSON = "application/json";

    private final JweKeyHolder keyHolder;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain)
            throws ServletException, IOException {

        if (!isJweRequest(request)) {
            chain.doFilter(request, response);
            return;
        }

        byte[] plainBody = decryptRequestBody(request, response);
        if (plainBody == null) {
            return;
        }

        JweRequestWrapper wrappedRequest = new JweRequestWrapper(request, plainBody);
        JweResponseWrapper wrappedResponse = new JweResponseWrapper(response);

        chain.doFilter(wrappedRequest, wrappedResponse);

        RSAPublicKey recipientKey = resolveRecipientKey(request, response);
        if (recipientKey == null) {
            return;
        }
        encryptAndWrite(wrappedResponse, response, recipientKey);
    }

    private boolean isJweRequest(HttpServletRequest request) {
        return "true".equalsIgnoreCase(request.getHeader(HEADER_JWE_FLAG))
            || CONTENT_TYPE_JOSE.equalsIgnoreCase(request.getContentType());
    }

    private byte[] decryptRequestBody(HttpServletRequest request,
                                      HttpServletResponse response) throws IOException {
        try {
            byte[] raw = request.getInputStream().readAllBytes();
            if (raw.length == 0) {
                return new byte[0];
            }
            return keyHolder.decrypt(new String(raw, StandardCharsets.UTF_8).strip());
        } catch (Exception e) {
            sendError(response, HttpServletResponse.SC_BAD_REQUEST, "JWE decryption failed");
            return null;
        }
    }

    private RSAPublicKey resolveRecipientKey(HttpServletRequest request,
                                             HttpServletResponse response) throws IOException {
        String clientKeyHeader = request.getHeader(HEADER_CLIENT_PUBLIC_KEY);
        if (clientKeyHeader == null) {
            return keyHolder.publicKey();
        }
        try {
            byte[] der = Base64.getDecoder().decode(clientKeyHeader.strip());
            return (RSAPublicKey) KeyFactory.getInstance("RSA")
                .generatePublic(new X509EncodedKeySpec(der));
        } catch (Exception e) {
            sendError(response, HttpServletResponse.SC_BAD_REQUEST, "Invalid X-Client-Public-Key");
            return null;
        }
    }

    private void encryptAndWrite(JweResponseWrapper wrappedResponse,
                                 HttpServletResponse response,
                                 RSAPublicKey recipientKey) throws IOException {
        byte[] captured = wrappedResponse.capturedBody();
        try {
            byte[] encrypted = keyHolder.encryptForRecipient(captured, recipientKey)
                .getBytes(StandardCharsets.UTF_8);
            response.setContentType(CONTENT_TYPE_JOSE);
            response.setContentLength(encrypted.length);
            response.getOutputStream().write(encrypted);
        } catch (Exception e) {
            sendError(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "JWE encryption failed");
        }
    }

    private void sendError(HttpServletResponse response, int status, String message) throws IOException {
        response.setStatus(status);
        response.setContentType(CONTENT_TYPE_JSON);
        byte[] body = ("{\"error\":\"" + message + "\"}").getBytes(StandardCharsets.UTF_8);
        response.setContentLength(body.length);
        response.getOutputStream().write(body);
    }
}
