package com.isc.sentinel.vendor.luna;

import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import java.security.Key;
import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;

/**
 * Logs in to a Luna / ProtectToolkit partition and exposes a JCE {@link Provider}
 * plus a logged-in {@link KeyStore} for token-object access.
 *
 * Two provider backends (config {@code luna.provider-type}):
 *   - {@code safenet} (default) — the vendor JCE provider
 *     ({@code au.com.safenet.crypto.provider.SAFENETProvider}, KeyStore type
 *     {@code CRYPTOKI}), loaded by reflection so this module compiles without the
 *     proprietary jar (jprov_sfnt.jar is supplied on the runtime classpath). The
 *     vendor provider supports persistent token *secret* keys, which the JDK
 *     SunPKCS11 keystore does not.
 *   - {@code sunpkcs11} — JDK SunPKCS11 against a cryptoki library ({@code luna.library}).
 *     Works for session crypto but cannot persist secret keys as token objects.
 *
 * Config:
 *   luna.enabled        = true|false   (default false — adapter degrades to ERROR)
 *   luna.provider-type  = safenet|sunpkcs11  (default safenet)
 *   luna.library        = cryptoki .so path   (sunpkcs11 only)
 *   luna.slot           = partition slot index (default 0)
 *   luna.pin            = partition user PIN
 *
 * On any init failure the manager stays un-ready and the adapter returns ERROR
 * rather than crashing the gateway.
 */
@Slf4j
@Component
public class LunaProviderManager {

    private static final String SAFENET_PROVIDER = "au.com.safenet.crypto.provider.SAFENETProvider";

    @Value("${luna.enabled:false}")          private boolean enabled;
    @Value("${luna.provider-type:safenet}")  private String  providerType;
    @Value("${luna.name:luna}")              private String  name;
    @Value("${luna.library:}")               private String  library;
    @Value("${luna.slot:0}")                 private long    slot;
    @Value("${luna.pin:}")                   private String  pin;

    private volatile Provider provider;
    private volatile KeyStore keyStore;
    private volatile Object   wrappingKeyStore;   // au.com.safenet.crypto.WrappingKeyStore (reflective)

    @PostConstruct
    void init() {
        if (!enabled) {
            log.info("Luna adapter disabled (luna.enabled=false)");
            return;
        }
        try {
            char[] pwd = pin == null ? new char[0] : pin.toCharArray();
            Provider p;
            KeyStore ks;

            if ("sunpkcs11".equalsIgnoreCase(providerType)) {
                if (library == null || library.isBlank()) {
                    log.warn("luna.provider-type=sunpkcs11 but luna.library is empty — Luna adapter offline");
                    return;
                }
                Provider base = Security.getProvider("SunPKCS11");
                if (base == null) { log.error("SunPKCS11 not present in this JRE — Luna adapter offline"); return; }
                p = base.configure("--name = " + name + "\nlibrary = " + library + "\nslot = " + slot + "\n");
                Security.addProvider(p);
                ks = KeyStore.getInstance("PKCS11", p);
            } else {
                // SAFENET / ProtectToolkit JProv — reflective so no compile-time jar dependency.
                p = (Provider) Class.forName(SAFENET_PROVIDER).getDeclaredConstructor().newInstance();
                Security.addProvider(p);
                ks = KeyStore.getInstance("CRYPTOKI", p);
                // WrappingKeyStore does C_UnwrapKey (JProv Cipher has no UNWRAP mode).
                this.wrappingKeyStore = Class.forName("au.com.safenet.crypto.WrappingKeyStore")
                    .getMethod("getInstance", String.class, String.class)
                    .invoke(null, "CRYPTOKI", p.getName());
            }

            ks.load(null, pwd);   // C_Login against the partition
            this.provider = p;
            this.keyStore = ks;
            log.info("Luna provider '{}' online — type={} slot={} keystore aliases={}",
                     p.getName(), providerType, slot, ks.size());
        } catch (Exception e) {
            log.error("Luna provider init failed ({}): {} — adapter offline",
                      e.getClass().getSimpleName(), e.getMessage());
            this.provider = null;
            this.keyStore = null;
        }
    }

    /** True only when the partition is logged in and ready for crypto. */
    public boolean isReady() {
        return provider != null && keyStore != null;
    }

    public Provider provider() {
        if (provider == null) throw new IllegalStateException("Luna provider not initialized");
        return provider;
    }

    public KeyStore keyStore() {
        if (keyStore == null) throw new IllegalStateException("Luna keystore not initialized");
        return keyStore;
    }

    /**
     * Unwrap a key inside the HSM (clear bytes never reach host). Uses the vendor
     * WrappingKeyStore for SAFENET (JProv Cipher has no UNWRAP mode); falls back to
     * JCE Cipher UNWRAP_MODE for SunPKCS11.
     *
     * @param wrappingKey the KEK already resident in the token (e.g. the ZMK)
     * @param wrapAlgo    wrap transformation, e.g. "DESede/ECB/NoPadding"
     * @param wrapped     the wrapped key bytes
     * @param keyAlgo     algorithm of the unwrapped key, e.g. "DESede"
     */
    public Key unwrapKey(Key wrappingKey, String wrapAlgo, byte[] wrapped, String keyAlgo) throws Exception {
        if (wrappingKeyStore != null) {
            try {
                return (Key) wrappingKeyStore.getClass()
                    .getMethod("unwrapKey", Key.class, String.class, byte[].class, String.class)
                    .invoke(wrappingKeyStore, wrappingKey, wrapAlgo, wrapped, keyAlgo);
            } catch (java.lang.reflect.InvocationTargetException ite) {
                // Surface the real vendor cause (e.g. CKR_KEY_FUNCTION_NOT_PERMITTED)
                // instead of an opaque InvocationTargetException with a null message.
                Throwable cause = ite.getTargetException();
                if (cause instanceof Exception ex) throw ex;
                throw new RuntimeException(cause);
            }
        }
        Cipher c = Cipher.getInstance(keyAlgo, provider());
        c.init(Cipher.UNWRAP_MODE, wrappingKey);
        return c.unwrap(wrapped, keyAlgo, Cipher.SECRET_KEY);
    }

    /** Provider display name + version for status/echo ops. */
    public String describe() {
        return provider == null ? "offline"
            : provider.getName() + " v" + provider.getVersionStr();
    }
}
