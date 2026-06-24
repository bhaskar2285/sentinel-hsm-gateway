package com.isc.sentinel.api.jwe;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;

/**
 * Holds the gateway's RSA key pair for the JWE body-encryption layer.
 *
 * IMPORTANT: JWE here is defense-in-depth ONLY. It encrypts request/response
 * bodies but is not transport security — TLS is. Do not rely on JWE in place of
 * TLS: without TLS the public key is fetched over an unauthenticated channel and
 * can be MITM-swapped, and headers/JWT bearer tokens are not protected.
 *
 * The key pair is PERSISTED (PKCS#8 private key at sentinel.jwe.key-path) so it
 * survives restarts instead of silently rotating on every boot. Rotation is
 * deliberate (rotate()), and the public key should be distributed to clients
 * out-of-band (signed cert / pinned fingerprint), not trusted blindly from the
 * /jwe/public-key endpoint.
 */
@Component
public class JweKeyHolder {

    private static final Logger log = LoggerFactory.getLogger(JweKeyHolder.class);

    private static final int RSA_KEY_BITS = 3072;
    private static final JWEAlgorithm KEY_ALGORITHM = JWEAlgorithm.RSA_OAEP_256;
    private static final EncryptionMethod CONTENT_ALGORITHM = EncryptionMethod.A256GCM;

    private final String keyPath;
    private final boolean persist;

    private volatile RSAPublicKey publicKey;
    private volatile RSAPrivateKey privateKey;

    public JweKeyHolder(
            @Value("${sentinel.jwe.key-path:/app/jwe/jwe-key.der}") String keyPath,
            @Value("${sentinel.jwe.persist:true}") boolean persist) {
        this.keyPath = keyPath;
        this.persist = persist;
    }

    @PostConstruct
    public synchronized void init() throws Exception {
        Path path = Path.of(keyPath);
        if (persist && Files.isReadable(path)) {
            loadFromDisk(path);
            log.info("JWE key pair loaded from {}", keyPath);
        } else {
            boolean persisted = generateAndStore(path);
            log.info("JWE key pair generated ({})",
                persisted ? "persisted to " + keyPath : "in-memory only — will rotate on next restart");
        }
    }

    /** Deliberately generate a fresh key pair, persisting it. Old JWE blobs become undecryptable. */
    public synchronized void rotate() throws Exception {
        generateAndStore(Path.of(keyPath));
        log.warn("JWE key pair ROTATED. Redistribute the new public key out-of-band to clients.");
    }

    private void loadFromDisk(Path path) throws Exception {
        byte[] pkcs8 = Files.readAllBytes(path);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        RSAPrivateCrtKey priv = (RSAPrivateCrtKey) kf.generatePrivate(new PKCS8EncodedKeySpec(pkcs8));
        RSAPublicKey pub = (RSAPublicKey) kf.generatePublic(
            new RSAPublicKeySpec(priv.getModulus(), priv.getPublicExponent()));
        this.privateKey = priv;
        this.publicKey = pub;
    }

    private boolean generateAndStore(Path path) throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(RSA_KEY_BITS);
        KeyPair pair = gen.generateKeyPair();
        this.publicKey = (RSAPublicKey) pair.getPublic();
        this.privateKey = (RSAPrivateKey) pair.getPrivate();
        if (!persist) {
            return false;
        }
        try {
            if (path.getParent() != null) Files.createDirectories(path.getParent());
            Files.write(path, privateKey.getEncoded());
            trySetOwnerReadOnly(path);
            return true;
        } catch (Exception e) {
            log.warn("Could not persist JWE key to {} ({}). Continuing in-memory.", keyPath, e.getMessage());
            return false;
        }
    }

    private void trySetOwnerReadOnly(Path path) {
        try {
            Files.setPosixFilePermissions(path, java.util.Set.of(
                java.nio.file.attribute.PosixFilePermission.OWNER_READ,
                java.nio.file.attribute.PosixFilePermission.OWNER_WRITE));
        } catch (Exception ignored) {
            // non-POSIX filesystem — best effort
        }
    }

    public RSAPublicKey publicKey() {
        return publicKey;
    }

    public byte[] decrypt(String compactJwe) throws Exception {
        JWEObject jweObject = JWEObject.parse(compactJwe);
        jweObject.decrypt(new RSADecrypter(privateKey));
        return jweObject.getPayload().toBytes();
    }

    public String encrypt(byte[] plaintext) throws Exception {
        return encryptForRecipient(plaintext, publicKey);
    }

    public String encryptForRecipient(byte[] plaintext, RSAPublicKey recipientKey) throws Exception {
        JWEObject jweObject = new JWEObject(
            new JWEHeader(KEY_ALGORITHM, CONTENT_ALGORITHM),
            new Payload(plaintext)
        );
        jweObject.encrypt(new RSAEncrypter(recipientKey));
        return jweObject.serialize();
    }
}
