package com.isc.sentinel.api.jwe;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import jakarta.annotation.PostConstruct;
import org.springframework.stereotype.Component;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

@Component
public class JweKeyHolder {

    private static final int RSA_KEY_BITS = 2048;
    private static final JWEAlgorithm KEY_ALGORITHM = JWEAlgorithm.RSA_OAEP_256;
    private static final EncryptionMethod CONTENT_ALGORITHM = EncryptionMethod.A256GCM;

    private RSAPublicKey publicKey;
    private RSAPrivateKey privateKey;

    @PostConstruct
    public void generateKeyPair() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(RSA_KEY_BITS);
        KeyPair pair = gen.generateKeyPair();
        publicKey = (RSAPublicKey) pair.getPublic();
        privateKey = (RSAPrivateKey) pair.getPrivate();
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
