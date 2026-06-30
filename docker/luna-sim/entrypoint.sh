#!/usr/bin/env bash
# Init the PTK software token, then launch the gateway with the Luna PKCS#11 adapter
# pointed at the in-container libcryptoki.so.
set -u

/usr/local/bin/init-token.sh || true

# Run via PropertiesLauncher so the vendor JProv jar joins the Spring Boot classpath
# (loader.path). luna.provider-type=safenet uses au.com.safenet...SAFENETProvider +
# KeyStore CRYPTOKI, which can persist token secret keys.
exec java \
    -Dloader.path=/app/jprov_sfnt.jar \
    -Dluna.enabled=true \
    -Dluna.provider-type=safenet \
    -Dluna.slot=0 \
    -Dluna.pin="${USER_PIN:-sentinel123}" \
    -cp /app/app.jar \
    org.springframework.boot.loader.launch.PropertiesLauncher
