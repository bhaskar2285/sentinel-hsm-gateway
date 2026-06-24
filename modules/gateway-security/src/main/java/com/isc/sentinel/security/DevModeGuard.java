package com.isc.sentinel.security;

import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.net.InetAddress;

/**
 * Refuses to start in dev-mode (authentication disabled) when the server is
 * bound to anything other than loopback, unless explicitly overridden.
 *
 * dev-mode permits every request as ROLE_ADMIN with all OP_* authorities. It is
 * only ever safe on a developer's own machine. Binding it to a routable
 * interface exposes the full HSM command surface unauthenticated.
 *
 * Override for a deliberate local-LAN demo with SENTINEL_DEV_ALLOW_REMOTE=true.
 */
@Component
public class DevModeGuard {

    private static final Logger log = LoggerFactory.getLogger(DevModeGuard.class);

    private final boolean devMode;
    private final String bindAddress;
    private final boolean allowRemote;

    public DevModeGuard(
            @Value("${sentinel.security.dev-mode:false}") boolean devMode,
            @Value("${server.address:}") String bindAddress,
            @Value("${sentinel.security.dev-allow-remote:${SENTINEL_DEV_ALLOW_REMOTE:false}}") boolean allowRemote) {
        this.devMode = devMode;
        this.bindAddress = bindAddress;
        this.allowRemote = allowRemote;
    }

    @PostConstruct
    void verify() {
        if (!devMode) {
            return;
        }
        if (allowRemote) {
            log.warn("dev-mode is ENABLED with dev-allow-remote=true: authentication is DISABLED "
                   + "and the HSM command surface is exposed without auth. Local/demo use only.");
            return;
        }
        if (isLoopbackBind()) {
            log.warn("dev-mode is ENABLED (authentication DISABLED) on loopback bind '{}'. "
                   + "Never use a secured deployment in dev-mode.",
                   bindAddress.isBlank() ? "127.0.0.1" : bindAddress);
            return;
        }
        throw new IllegalStateException(
            "Refusing to start: sentinel.security.dev-mode=true with a non-loopback bind ('"
          + (bindAddress.isBlank() ? "0.0.0.0 / all interfaces" : bindAddress) + "'). "
          + "dev-mode disables authentication. Use the secured profile (omit dev-mode) for any "
          + "non-local deployment, or set SENTINEL_DEV_ALLOW_REMOTE=true to override for a "
          + "deliberate local-only demo.");
    }

    private boolean isLoopbackBind() {
        if (bindAddress == null || bindAddress.isBlank()) {
            return false; // unset == bind all interfaces == reachable off-host
        }
        try {
            return InetAddress.getByName(bindAddress).isLoopbackAddress();
        } catch (Exception e) {
            return false;
        }
    }
}
