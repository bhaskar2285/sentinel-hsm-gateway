# sentinel-hsm-gateway

Multi-vendor HSM gateway. Spring Boot 3.5, Java 25, Postgres 16.

## Purpose

Wraps complex Thales (and Utimaco) host commands into Cosmian-KMS-style REST APIs. Acts as:

- **Protocol translator** — REST/JSON ↔ vendor-native 2-letter command codes
- **Load balancer** — same-vendor pools (Thales→Thales, Utimaco→Utimaco)
- **Key vault** — persists key metadata + TR-31/X9.143 wrapped key material
- **Auth gate** — validates xenticate-auth JWT; RBAC per command
- **Direct HSM listener** — HSMs can dial in; gateway can also dial HSMs

Coexists with `thales-artemis-lb` (does not replace).

## Modules

| Module | Purpose |
|--------|---------|
| `gateway-api` | Spring Boot app, REST controllers, OpenAPI |
| `gateway-core` | OpCode, GatewayCommand DTOs, dispatcher, LB |
| `gateway-security` | JWT validation, RBAC mapping |
| `gateway-persistence` | JPA entities, Flyway |
| `gateway-keyblock` | TR-31 (Format B) + X9.143 codec |
| `gateway-vendor-spi` | `HsmVendorAdapter` interface |
| `gateway-vendor-thales` | Thales payShield 10K codec |
| `gateway-vendor-utimaco` | Utimaco stub |

## Phase 1 commands

| HTTP | Path | Vendor cmd | Description |
|------|------|-----------|-------------|
| POST | `/api/v1/keys/rsa` | EI/EJ | Generate RSA key pair |
| POST | `/api/v1/keys/import-rsa-wrapped` | GI/GJ | Import key/data wrapped under RSA pub |
| POST | `/api/v1/keys/{id}/export` | A8/A9 | Export key under another key |
| POST | `/api/v1/crypto/decrypt` | M2/M3 | Decrypt data block |

Phase 2: remaining ~165 Thales codes.

## Build

```
mvn -T 1C clean install
docker compose up -d
```

## Frontend

Separate repo: `sentinel-hsm-console`.
