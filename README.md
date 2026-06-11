# sentinel-hsm-gateway

Multi-vendor HSM gateway. Spring Boot 3.5, Java 25, Postgres 16.

## Purpose

Wraps complex Thales (and Utimaco) host commands into REST APIs. Acts as:

- **Protocol translator** — REST/JSON ↔ vendor-native 2-letter command codes
- **Load balancer** — same-vendor pools (Thales→Thales, Utimaco→Utimaco)
- **Key vault** — persists key metadata + TR-31/X9.143 wrapped key material
- **Auth gate** — validates Bearer token; RBAC per command
- **Direct HSM listener** — HSMs can dial in; gateway can also dial HSMs

Coexists with `thales-artemis-lb` (does not replace).

---

## Modules

| Module | Purpose |
|--------|---------|
| `gateway-api` | Spring Boot app, REST controllers, OpenAPI |
| `gateway-core` | OpCode, GatewayCommand DTOs, dispatcher, LB |
| `gateway-security` | JWT validation, RBAC mapping |
| `gateway-persistence` | JPA entities, Flyway |
| `gateway-keyblock` | TR-31 (Format B) + X9.143 codec |
| `gateway-vendor-spi` | `HsmVendorAdapter` interface |
| `gateway-vendor-thales` | Thales payShield 10K codec (`ThalesCmdBuilder` / `ThalesCmdParser`) |
| `gateway-vendor-utimaco` | Utimaco stub |

---

## API Design

Two parallel REST paths — same HSM adapter underneath:

| Path | Class | Use case |
|------|-------|----------|
| `POST /thales/command/{CMD}` | `ThalesCommandController` | Direct Thales command access; raw HSM-native params |
| `POST /api/v1/crypto/**` | `CryptoController` | Semantic high-level API; typed DTOs; payment app integration |
| `POST /api/v1/keys/**` | `KeyController` | Key lifecycle (generate, import, export, list) |

**Use `/thales/command/{CMD}` for:** HSM testing, direct integration, per-command control.  
**Use `/api/v1/crypto/**` for:** payment application integration, abstracted operations.

---

## Thales Command Reference

### ✅ Built + HSM Tested (confirmed err=00 on live HSM)

| Cmd | Endpoint | Description |
|-----|----------|-------------|
| NC | `POST /thales/command/NC` | Network connectivity check |
| A0 | `POST /thales/command/A0` | Generate symmetric key under LMK |
| A6 | `POST /thales/command/A6` | Import key encrypted under ZMK → LMK |
| A8 | `POST /thales/command/A8` | Export key from LMK → ZMK encryption |
| BU | `POST /thales/command/BU` | Generate key check value (KCV) |
| GC | `POST /thales/command/GC` | Export ZPK from LMK to ZMK encryption |

---

### 🔶 Built, Not HSM Tested (wire format complete; awaiting full PayShield access)

#### Key Management

| Cmd | Endpoint | Description |
|-----|----------|-------------|
| A2 | `POST /thales/command/A2` | Generate random key component (clear) |
| A4 | `POST /thales/command/A4` | Form key from encrypted components |
| B4 | `POST /thales/command/B4` | Form TR-31 / X9.143 key block |
| EI | `POST /thales/command/EI` | Generate RSA key pair |
| GI | `POST /thales/command/GI` | Import key wrapped under RSA public key |
| HC | `POST /thales/command/HC` | Generate TPK under LMK |
| IA | `POST /thales/command/IA` | Generate ZPK under LMK |

#### Encrypt / Decrypt / MAC

| Cmd | Endpoint | Description |
|-----|----------|-------------|
| M0 | `POST /thales/command/M0` | Encrypt data block |
| M2 | `POST /thales/command/M2` | Decrypt data block |
| M6 | `POST /thales/command/M6` | Generate MAC |
| M8 | `POST /thales/command/M8` | Verify MAC |
| VA | `POST /thales/command/VA` | Verify MAC (full-format variant) |
| LQ | `POST /thales/command/LQ` | Generate HMAC (SPA2 AAV) |
| LS | `POST /thales/command/LS` | Verify HMAC |
| OA | `POST /thales/command/OA` | Generate random data |

#### PIN Operations

| Cmd | Endpoint | Description |
|-----|----------|-------------|
| JA | `POST /thales/command/JA` | Generate random PIN under LMK |
| BA | `POST /thales/command/BA` | Encrypt clear PIN under ZPK |
| NG | `POST /thales/command/NG` | Decrypt PIN block to clear |
| JC | `POST /thales/command/JC` | Translate PIN TPK → LMK |
| JE | `POST /thales/command/JE` | Translate PIN ZPK → LMK |
| JG | `POST /thales/command/JG` | Translate PIN LMK → ZPK |
| CC | `POST /thales/command/CC` | Translate PIN ZPK → ZPK |
| JS | `POST /thales/command/JS` | Translate PIN ZPK → ZPK (variant 2) |
| CA | `POST /thales/command/CA` | Translate PIN TPK → ZPK/BDK |
| DA | `POST /thales/command/DA` | Verify terminal PIN (IBM 3624 offset) |
| DC | `POST /thales/command/DC` | Verify terminal PIN (VISA PVV) |
| EA | `POST /thales/command/EA` | Verify interchange PIN (IBM 3624) |
| EC | `POST /thales/command/EC` | Verify interchange PIN (VISA PVV) |
| DE | `POST /thales/command/DE` | Generate IBM PIN offset |
| DG | `POST /thales/command/DG` | Generate VISA PVV |
| EE | `POST /thales/command/EE` | Derive PIN from IBM offset |

#### CVV / EMV

| Cmd | Endpoint | Description |
|-----|----------|-------------|
| CW | `POST /thales/command/CW` | Generate CVV/CVC/CVV2 |
| CY | `POST /thales/command/CY` | Verify CVV/CVC/CVV2 |
| KQ | `POST /thales/command/KQ` | Verify ARQC / Generate ARPC (EMV chip) |
| KW | `POST /thales/command/KW` | Verify ARQC / Generate ARPC (EMV 4.x) |
| PM | `POST /thales/command/PM` | Verify dynamic CVV/CVC (dCVV CVN17) |
| RY | `POST /thales/command/RY` | Calculate / verify card security code |

#### Diagnostics

| Cmd | Endpoint | Description |
|-----|----------|-------------|
| B2 | `POST /thales/command/B2` | Echo / loopback |
| NO | `POST /thales/command/NO` | HSM status (firmware, LMK check value) |

---

### ❌ Not Built (pending)

| Cmd | Description | Notes |
|-----|-------------|-------|
| PA  | Generate PIN (legacy) | PA/PB pair |
| PC  | Verify PIN (legacy) | PC/PD pair |
| PE  | Translate PIN (legacy) | PE/PF pair |
| GO  | Generate key (AES/alt) | GO/GP pair |
| G0  | Generate key (variant) | G-zero variant |
| BG  | Generate key check value (alt) | BG/BH pair; variant of BU |
| NH  | *(response code only)* | NH is the response to NG — not a request command |

---

## Implementation Guide

### Authentication

All endpoints require a Bearer token:

```bash
# Login
curl -X POST http://localhost:8090/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"loginname":"admin","password":"sentinel123"}'
# Response: {"token":"<hex-token>"}

# Use token
curl -H "Authorization: Bearer <token>" ...
```

---

### Common concepts

**keyType codes** differ per command:

| Command | Type code | Key type |
|---------|-----------|----------|
| A0 | `000` | ZMK |
| A0 | `001` | ZPK |
| A0 | `002` | TPK |
| A0 | `00A` | DATA |
| BU | `001` | ZMK |
| BU | `011` | ZPK |
| BU | `008` | TMK/TPK |

**Key schemes:**

| Code | Type | Key length |
|------|------|-----------|
| `U` | Double-length DES | 16 bytes / 32 hex chars |
| `T` | Triple-length DES | 24 bytes / 48 hex chars |
| `X` | AES-128 | 16 bytes / 32 hex chars |

**Important:** params are passed directly to `ThalesCmdBuilder` — use HSM-native codes, not names like `"ZMK"`.

---

### NC — Network Connectivity Check

```bash
curl -X POST http://localhost:8090/thales/command/NC \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{}'
```

Response:
```json
{"errCode":"00","errText":"No error","status":"OK"}
```

---

### A0 — Generate Symmetric Key

```bash
curl -X POST http://localhost:8090/thales/command/A0 \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"keyType":"000","keyScheme":"U"}'
```

Params:

| Param | Required | Description |
|-------|----------|-------------|
| `keyType` | yes | 3-char HSM code: `000`=ZMK, `001`=ZPK, `002`=TPK, `00A`=DATA |
| `keyScheme` | yes | `U` (double-DES) or `T` (triple-DES) |

Response:
```json
{
  "keyUnderLmk": "E472EA21818D80C6D425CFB9508B29A0",
  "scheme": "U",
  "kcv": "72ABD5",
  "errCode": "00",
  "status": "OK"
}
```

---

### BU — Generate Key Check Value (KCV)

`keyType` uses BU-specific codes (different from A0).

```bash
curl -X POST http://localhost:8090/thales/command/BU \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"keyType":"001","scheme":"U","keyHex":"E472EA21818D80C6D425CFB9508B29A0"}'
```

Params:

| Param | Required | Description |
|-------|----------|-------------|
| `keyType` | yes | BU code: `001`=ZMK, `011`=ZPK, `008`=TPK |
| `scheme` | yes | `U` or `T` |
| `keyHex` | yes | Key under LMK — hex only, no scheme prefix |

Response:
```json
{"kcv":"72ABD5","errCode":"00","status":"OK"}
```

---

### GC — Export ZPK under ZMK (LMK → ZMK)

```bash
curl -X POST http://localhost:8090/thales/command/GC \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "zmkScheme": "U",
    "zmkHex":    "<zmk-under-lmk-hex>",
    "zpkScheme": "U",
    "zpkHex":    "<zpk-under-lmk-hex>"
  }'
```

Response:
```json
{
  "zpkUnderZmk": "00857FD7BE5C85685CE24074DA43490E",
  "scheme": "U",
  "kcv": "7D227C",
  "errCode": "00",
  "status": "OK"
}
```

---

### A6 — Import Key (ZMK-encrypted → LMK)

```bash
curl -X POST http://localhost:8090/thales/command/A6 \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "keyType":      "001",
    "zmkScheme":    "U",
    "zmkUnderLmk":  "<zmk-under-lmk-hex>",
    "keyScheme":    "U",
    "keyUnderZmk":  "<zpk-under-zmk-hex>",
    "lmkScheme":    "U"
  }'
```

Response:
```json
{
  "keyUnderLmk": "EAB815FCCD029F57576CA1EC45CF0245",
  "scheme": "U",
  "kcv": "7D227C",
  "errCode": "00",
  "status": "OK"
}
```

---

### A8 — Export Key (LMK → ZMK)

```bash
curl -X POST http://localhost:8090/thales/command/A8 \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "keyKeyType":   "001",
    "zmkScheme":    "U",
    "zmkUnderLmk":  "<zmk-under-lmk-hex>",
    "keyScheme":    "U",
    "keyUnderLmk":  "<zpk-under-lmk-hex>",
    "outScheme":    "U"
  }'
```

Response:
```json
{
  "keyUnderZmk": "00857FD7BE5C85685CE24074DA43490E",
  "scheme": "U",
  "kcv": "7D227C",
  "errCode": "00",
  "status": "OK"
}
```

---

### Typical ZMK/ZPK workflow

```
1. Generate ZMK:   A0 keyType=000 → zmkUnderLmk
2. Generate ZPK:   A0 keyType=001 → zpkUnderLmk
3. Verify KCVs:    BU keyType=001 (ZMK), BU keyType=011 (ZPK)
4. Export ZPK:     GC zmkHex + zpkHex → zpkUnderZmk  (send to ATM/POS)
5. Import ZPK:     A6 zmkUnderLmk + zpkUnderZmk → zpkUnderLmk (receive from external)
6. Re-export ZPK:  A8 zmkUnderLmk + zpkUnderLmk → zpkUnderZmk
```

---

## Wire Protocol

```
Request frame:  [2-byte BE length][4-byte ASCII "0000"][2-byte cmd][body]
Response frame: [2-byte BE length][4-byte ASCII "0000"][2-byte resp-cmd][2-byte err-code][body]
```

Error code `00` = success. All other codes defined in `ThalesErrorCode.java`.

Key classes:

| Class | Location | Role |
|-------|----------|------|
| `ThalesCmdBuilder` | `gateway-vendor-thales` | Params map → HSM wire frame |
| `ThalesCmdParser` | `gateway-vendor-thales` | HSM response bytes → fields map |
| `ThalesVendorAdapter` | `gateway-vendor-thales` | OpCode dispatch, TCP roundtrip |
| `CommandDispatcher` | `gateway-core` | Vendor routing, audit |
| `ThalesCommandController` | `gateway-api` | `/thales/command/{cmd}` routing |

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

Separate repo: `sentinel-vault-ui`.
