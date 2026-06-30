package com.isc.sentinel.vendor.luna;

import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;

/**
 * Manual smoke test -- run inside the amd64 PTK image after init-token.sh.
 * Proves the JDK SunPKCS11 provider can load the ProtectToolkit cryptoki
 * library and C_Login to Slot 0 as the normal user.
 *
 *   javac -d /tmp SmokeMain.java
 *   java -cp /tmp com.isc.sentinel.vendor.luna.SmokeMain
 */
public class SmokeMain {
    public static void main(String[] args) throws Exception {
        String lib = System.getenv().getOrDefault(
            "LUNA_LIBRARY", "/opt/safenet/protecttoolkit7/ptk/lib/libcryptoki.so");
        String pin = System.getenv().getOrDefault("USER_PIN", "sentinel123");
        String cfg = "--name=luna\nlibrary=" + lib + "\nslot=0\n";

        Provider p = Security.getProvider("SunPKCS11").configure(cfg);
        Security.addProvider(p);
        KeyStore ks = KeyStore.getInstance("PKCS11", p);
        ks.load(null, pin.toCharArray());
        System.out.println("LOGIN OK provider=" + p.getName() + " aliases=" + ks.size());

        // prove a crypto op works: generate an AES key on the token
        javax.crypto.KeyGenerator kg = javax.crypto.KeyGenerator.getInstance("AES", p);
        kg.init(256);
        javax.crypto.SecretKey k = kg.generateKey();
        javax.crypto.Cipher c = javax.crypto.Cipher.getInstance("AES/ECB/NoPadding", p);
        c.init(javax.crypto.Cipher.ENCRYPT_MODE, k);
        byte[] ct = c.doFinal(new byte[16]);
        StringBuilder sb = new StringBuilder();
        for (byte b : ct) sb.append(String.format("%02X", b));
        System.out.println("AES KCV(zero-block)=" + sb.substring(0, 6));
    }
}
