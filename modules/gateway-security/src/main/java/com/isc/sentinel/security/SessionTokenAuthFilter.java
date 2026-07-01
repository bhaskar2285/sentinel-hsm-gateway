package com.isc.sentinel.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Set;

/**
 * Authenticates a request against the gateway's own opaque session tokens
 * (issued by AuthService.login, stored in isc_sam_session).
 *
 * Token is read from {@code Authorization: Bearer <token>} or
 * {@code X-Session-Token}. A session is valid when it is active (record_status
 * 'Y'), not logged out, and not expired. On success the request is populated
 * with the staff's RBAC authorities (ROLE_* / OP_*) so method-security
 * @PreAuthorize checks work without any external OAuth issuer.
 */
public class SessionTokenAuthFilter extends OncePerRequestFilter {

    private static final String BEARER_PREFIX = "Bearer ";
    private static final String HEADER_SESSION = "X-Session-Token";

    private static final String SQL_LOOKUP = """
        SELECT sam_staff_id FROM isc_sam_session
        WHERE session_token = ?
          AND record_status = 'Y'
          AND logout_at IS NULL
          AND expires_at > NOW()
        """;

    // Sliding expiration: extend a valid session to NOW()+1h on activity, but only when
    // it is within the last few minutes (caps the window to ~1h of *inactivity* while
    // avoiding a DB write on every request from an active session).
    private static final String SQL_TOUCH = """
        UPDATE isc_sam_session
        SET expires_at = NOW() + INTERVAL '1 hour'
        WHERE session_token = ?
          AND record_status = 'Y'
          AND logout_at IS NULL
          AND expires_at > NOW()
          AND expires_at < NOW() + INTERVAL '55 minutes'
        """;

    private final JdbcTemplate jdbc;
    private final RbacAuthorityResolver authorities;

    public SessionTokenAuthFilter(JdbcTemplate jdbc, RbacAuthorityResolver authorities) {
        this.jdbc = jdbc;
        this.authorities = authorities;
    }

    /**
     * Authenticate ERROR dispatches too. By default OncePerRequestFilter skips the
     * internal /error re-dispatch that Spring performs after an unhandled exception;
     * with the filter skipped the request reaches the authenticated /error endpoint
     * unauthenticated and returns 401 — making every 500 look like a session logout.
     * Returning false keeps the session authenticated on the error dispatch so the
     * real status code (400/500) is returned.
     */
    @Override
    protected boolean shouldNotFilterErrorDispatch() {
        return false;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {

        if (SecurityContextHolder.getContext().getAuthentication() == null) {
            String token = extractToken(request);
            if (token != null) {
                Long staffId = lookupStaff(token);
                if (staffId != null) {
                    Set<GrantedAuthority> auths = authorities.resolve(staffId);
                    var authentication = new PreAuthenticatedAuthenticationToken(
                        String.valueOf(staffId), token, auths);
                    authentication.setDetails(
                        new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                    touch(token);   // sliding expiration — keep active sessions alive
                }
            }
        }
        chain.doFilter(request, response);
    }

    private String extractToken(HttpServletRequest request) {
        String auth = request.getHeader("Authorization");
        if (auth != null && auth.regionMatches(true, 0, BEARER_PREFIX, 0, BEARER_PREFIX.length())) {
            String t = auth.substring(BEARER_PREFIX.length()).strip();
            if (!t.isEmpty()) return t;
        }
        String x = request.getHeader(HEADER_SESSION);
        if (x != null && !x.strip().isEmpty()) return x.strip();
        return null;
    }

    private Long lookupStaff(String token) {
        try {
            return jdbc.queryForObject(SQL_LOOKUP, Long.class, token);
        } catch (EmptyResultDataAccessException e) {
            return null; // unknown / expired / logged-out token -> stays unauthenticated
        }
    }

    /** Sliding expiration — refresh a valid session's expiry on activity. Best-effort. */
    private void touch(String token) {
        try {
            jdbc.update(SQL_TOUCH, token);
        } catch (Exception ignore) {
            // never block the request on a touch failure
        }
    }
}
