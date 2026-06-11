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

---

## Thales Command Status

### ✅ Built + HSM Tested (confirmed err=00 on live HSM)

| Cmd | REST Endpoint | Description |
|-----|--------------|-------------|
| NC | `GET /api/v1/crypto/hsm/status` | Network connectivity check |
| A0 | `POST /api/v1/keys/symmetric` | Generate symmetric key under LMK (ZMK/ZPK/TPK/DATA) |
| A6 | `POST /api/v1/keys/import-zmk-wrapped` | Import key encrypted under ZMK |
| A8 | `POST /api/v1/keys/{id}/export` | Export key encrypted under ZMK/KBPK |
| BU | `POST /api/v1/crypto/key/check-value` | Generate key check value (KCV) |
| GC | `POST /api/v1/crypto/key/export-zmk` | Export ZPK from LMK to ZMK encryption |

---

### 🔶 Built, Not HSM Tested (wire format complete; awaiting full PayShield access)

#### Key Management

| Cmd | REST Endpoint | Description |
|-----|--------------|-------------|
| A2 | `POST /api/v1/crypto/key/component/generate` | Generate random key component (clear) |
| A4 | `POST /api/v1/crypto/key/form-from-components` | Form key from encrypted components |
| B4 | — | Form TR-31 / X9.143 key block |
| EI | `POST /api/v1/keys/rsa` | Generate RSA key pair |
| GI | `POST /api/v1/keys/import-rsa-wrapped` | Import key wrapped under RSA public key |
| HC | `POST /api/v1/crypto/key/generate-tpk` | Generate TPK under LMK |
| IA | `POST /api/v1/crypto/key/generate-zpk` | Generate ZPK under LMK |

#### Encrypt / Decrypt / MAC

| Cmd | REST Endpoint | Description |
|-----|--------------|-------------|
| M0 | `POST /api/v1/crypto/encrypt` | Encrypt data block |
| M2 | `POST /api/v1/crypto/decrypt` | Decrypt data block |
| M6 | `POST /api/v1/crypto/mac/generate` | Generate MAC |
| M8 | `POST /api/v1/crypto/mac/verify` | Verify MAC |
| VA | `POST /api/v1/crypto/mac/verify-alt` | Verify MAC (full-format variant) |
| LQ | `POST /api/v1/crypto/hmac/generate` | Generate HMAC (SPA2 AAV) |
| LS | `POST /api/v1/crypto/hmac/verify` | Verify HMAC |
| OA | `POST /api/v1/crypto/random` | Generate random data |

#### PIN Operations

| Cmd | REST Endpoint | Description |
|-----|--------------|-------------|
| JA | `POST /api/v1/crypto/pin/generate` | Generate random PIN under LMK |
| BA | `POST /api/v1/crypto/pin/encrypt-clear` | Encrypt clear PIN under ZPK |
| NG | `POST /api/v1/crypto/pin/decrypt` | Decrypt PIN block to clear |
| JC | `POST /api/v1/crypto/pin/to-lmk` | Translate PIN TPK → LMK |
| JE | `POST /api/v1/crypto/pin/to-lmk` | Translate PIN ZPK → LMK |
| JG | `POST /api/v1/crypto/pin/from-lmk` | Translate PIN LMK → ZPK |
| CC | `POST /api/v1/crypto/pin/translate` | Translate PIN ZPK → ZPK |
| JS | `POST /api/v1/crypto/pin/translate-zpk2` | Translate PIN ZPK → ZPK (variant 2) |
| CA | `POST /api/v1/crypto/pin/translate-zpk` | Translate PIN TPK → ZPK/BDK |
| DA | `POST /api/v1/crypto/pin/verify` | Verify terminal PIN (IBM 3624 offset) |
| DC | `POST /api/v1/crypto/pin/verify-visa` | Verify terminal PIN (VISA PVV) |
| EA | `POST /api/v1/crypto/pin/verify-interchange-ibm` | Verify interchange PIN (IBM 3624) |
| EC | `POST /api/v1/crypto/pin/verify-interchange-visa` | Verify interchange PIN (VISA PVV) |
| DE | `POST /api/v1/crypto/pin/ibm-offset` | Generate IBM PIN offset |
| DG | `POST /api/v1/crypto/pin/pvv` | Generate VISA PVV |
| EE | `POST /api/v1/crypto/pin/derive-ibm` | Derive PIN from IBM offset |

#### CVV / EMV

| Cmd | REST Endpoint | Description |
|-----|--------------|-------------|
| CW | `POST /api/v1/crypto/cvv/generate` | Generate CVV/CVC/CVV2 |
| CY | `POST /api/v1/crypto/cvv/verify` | Verify CVV/CVC/CVV2 |
| KQ | `POST /api/v1/crypto/arqc` | Verify ARQC / Generate ARPC (EMV chip) |
| KW | `POST /api/v1/crypto/arqc/emv4` | Verify ARQC / Generate ARPC (EMV 4.x) |
| PM | `POST /api/v1/crypto/dcvv/verify` | Verify dynamic CVV/CVC (dCVV CVN17) |
| RY | `POST /api/v1/crypto/csc/calculate` `POST /api/v1/crypto/csc/verify` | Calculate / verify card security code |

#### Diagnostics

| Cmd | REST Endpoint | Description |
|-----|--------------|-------------|
| B2 | `POST /api/v1/crypto/hsm/echo` | Echo / loopback |
| NO | `GET /api/v1/crypto/hsm/status` | HSM status (firmware, LMK check value) |

---

### ❌ Not Built (no implementation — pending)

| Cmd | Description | Notes |
|-----|-------------|-------|
| PA  | Generate PIN (legacy) | Older Thales command; PA/PB pair |
| PC  | Verify PIN (legacy) | Older Thales command; PC/PD pair |
| PE  | Translate PIN (legacy) | Older Thales command; PE/PF pair |
| GO  | Generate key (AES/alt) | Variant key generation; GO/GP pair |
| G0  | Generate key (variant) | G-zero; purpose TBD from spec |
| BG  | Generate key check value (alt) | BG/BH pair; variant of BU |
| NH  | *(response code only)* | NH is the response to NG — not a separate request command |

---

## Wire Protocol

```
Request frame:  [2-byte BE length][4-byte ASCII header "0000"][2-byte cmd][body]
Response frame: [2-byte BE length][4-byte ASCII header "0000"][2-byte resp-cmd][2-byte err-code][body]
```

Error code `00` = success. All other codes defined in `ThalesErrorCode.java`.

Key scheme prefixes: `U` = double-length DES (16 bytes / 32 hex), `T` = triple-length DES (24 bytes / 48 hex), `X` = AES-128 (16 bytes / 32 hex).

---

## Build

```bash
mvn -T 1C clean package -DskipTests
docker compose build --no-cache gateway
docker compose up -d --force-recreate gateway
```

## Database

Postgres on host port **5434**. Flyway manages schema — do not edit applied migrations.

Default console credentials: `admin` / `sentinel123`

## Frontend

Separate repo: `sentinelvaultui`.
