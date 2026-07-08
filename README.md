# sentinel-hsm-gateway

Multi-vendor HSM gateway. Spring Boot 4.1, Java 25, Postgres 16.

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

`/api/v1/crypto/decrypt` returns `plaintextHex` as hex (`outputFormat` defaults to `1`).
Encrypt/decrypt default to mode `01` (CBC) — supply an `iv`, or set `mode:"00"` for ECB.

HSM nodes are configured in the DB via `/api/v1/hsms` (pool via `/api/v1/pools`); the
dispatcher routes only to nodes with `health=UP` (probed every 15s). The gateway runs
host networking, so a node `host:127.0.0.1 port:1500` reaches a host-local payShield.

---

## Switching App Integration

A switching / payment application talks to the HSM through the gateway only:

```
switching app  ->  Sentinel Gateway API  ->  Thales payShield HSM
```

Ready-to-use integration clients live in [`integration/`](integration/):

| Client | For |
|--------|-----|
| [`integration/sentinel_client.py`](integration/sentinel_client.py) | Python switches — `SentinelClient` wraps login, the raw `/thales/command/{CMD}` passthrough, and every semantic endpoint. Raises on any non-`00` HSM error. |
| [`integration/sentinel_client.sh`](integration/sentinel_client.sh) | Non-Python switches — `curl`/`jq` helper with `login` / `get` / `api` / `raw` verbs and self-healing token cache. |

```python
from sentinel_client import SentinelClient
sc = SentinelClient("http://gateway:8090", "admin", "sentinel123"); sc.login()
sc.cvv_generate(cvkKeyId=kid, pan="4111111111111111", expiry="2512", serviceCode="201")
sc.raw("M6", {"keyType":"008","keyScheme":"U","key":zak,"message":"48656C6C6F"})
```

```bash
./integration/sentinel_client.sh api /api/v1/crypto/hsm/echo '{"data":"DEADBEEF"}'
./integration/sentinel_client.sh raw M6 '{"keyType":"008","keyScheme":"U","key":"...","message":"..."}'
```

**Per-command usage** — operation, semantic endpoint, raw endpoint, key params,
and the console page for every command — is in
[`docs/COMMAND_GUIDE.md`](docs/COMMAND_GUIDE.md).

---

## Thales Command Reference

### ✅ Built + HSM Tested (confirmed err=00 on live payShield)

Verified end-to-end against the real payShield (RSM5 header) — request built by
`ThalesCmdBuilder`, replayed live, response parsed.

| Cmd | Endpoint | Description |
|-----|----------|-------------|
| NC | `POST /thales/command/NC` | Network connectivity check |
| NO | `POST /thales/command/NO` | HSM status (modes 00/01) |
| A0 | `POST /thales/command/A0` | Generate symmetric key (Variant **and** Key Block LMK) |
| A6 | `POST /thales/command/A6` | Import key encrypted under ZMK → LMK |
| A8 | `POST /thales/command/A8` | Export key from LMK → ZMK encryption |
| BU | `POST /thales/command/BU` | Generate key check value (KCV) |
| GC | `POST /thales/command/GC` | Export ZPK from LMK to ZMK encryption |
| M0 / M2 | `POST /thales/command/{M0,M2}` | Encrypt / decrypt data block (round-trip verified) |
| CA / CC | `POST /thales/command/{CA,CC}` | Translate PIN TPK→ZPK / ZPK→ZPK |
| JE / JG | `POST /thales/command/{JE,JG}` | Translate PIN ZPK↔LMK |
| DA / EA | `POST /thales/command/{DA,EA}` | Verify terminal / interchange PIN (IBM offset) |
| DG / EC | `POST /thales/command/{DG,EC}` | Generate VISA PVV / verify interchange PVV |
| CW / CY | `POST /thales/command/{CW,CY}` | Generate / verify CVV |
| BA / JA | `POST /thales/command/{BA,JA}` | Encrypt clear / generate random PIN under LMK |

> **DA/EA** return err **02** ("PVK not single length" warning) on success — the PIN is
> still verified; treat 00 and 02 as pass for double-length PVKs.

---

### Key Block LMK support

The live deployment runs a **Key Block LMK**. Key tokens use scheme tag **`S`** (3DES
key block) / **`R`** (imported TR-31 block) and are **self-describing**: the 4 decimal
digits after the scheme tag give the total token length (e.g. `S0007271TN00S0001…`
→ `0072` → 72 chars). `KeyScheme.keyTokenLen()` reads this; fixed schemes (`U`/`T`/`X`/
`Y`/`Z`) keep their static lengths. On a Key Block LMK the 3-digit key-type field is
implicit in the block header — commands that take a key block set key-type `FFF`
(M0/M2/M6) and omit the separate type prefix (DA/EA/CA).

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
| M6 | `POST /thales/command/M6` | Generate MAC (needs `FFF` + key block on this LMK) |
| M8 | `POST /thales/command/M8` | Verify MAC |
| VA | `POST /thales/command/VA` | Verify MAC (full-format variant) |
| LQ | `POST /thales/command/LQ` | Generate HMAC (SPA2 AAV) |
| LS | `POST /thales/command/LS` | Verify HMAC |
| OA | `POST /thales/command/OA` | Generate random data |

#### PIN Operations

| Cmd | Endpoint | Description |
|-----|----------|-------------|
| NG | `POST /thales/command/NG` | Decrypt PIN block to clear (err 17 here — CS-disabled) |
| JC | `POST /thales/command/JC` | Translate PIN TPK → LMK — **wire fixed**, mirrors live-verified JE |
| DC | `POST /thales/command/DC` | Verify terminal PIN (VISA PVV) — **wire fixed**, mirrors live-verified EC |
| DE | `POST /thales/command/DE` | Generate IBM PIN offset (verified vs real TTB key-block trace, DF02) |
| EE | `POST /thales/command/EE` | Derive PIN from IBM offset (layout matches manual) |

> `JC`/`DC` previously emitted a legacy key-type / MaxPIN prefix (same bug class as
> the earlier DA/EA fix) which the real HSM rejects with err 15. They now follow the
> Core Host Commands layout (DC p.266, JC p.283). `JD`/`JF`/`BH` responses parse the
> variable-length (13-char on this LMK) LMK-encrypted PIN, not a `pinLen+16H` field.
> Note: `JS` is **not** a standard payShield command — ZPK→ZPK PIN translate is `CC`.

#### CVV / EMV

| Cmd | Endpoint | Description |
|-----|----------|-------------|
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

### 🆕 Specialised commands (built; wire locked to spec)

Implemented from the Core Host Commands manual. Earlier docs mislabelled these as
"legacy PIN" ops — their real functions are below. `G0`/`GO` are recognised live on
the HSM; the rest build correct wire but need hardware/LMK setup not present here.

| Cmd | Real function | Live-testable here |
|-----|---------------|--------------------|
| PA  | Load Formatting Data to HSM (PIN-mailer print) | no — needs USB printer |
| PC  | Load Additional Formatting Data (follows PA) | no — needs printer |
| PE  | Print PIN / solicitation data | no — needs printer |
| BG  | Translate PIN old-LMK → new-LMK (LMK migration) | no — needs Key-Change LMKs |
| G0  | Translate PIN DUKPT → ZPK / DUKPT | yes — recognised (G1 responder) |
| GO  | Verify PIN (DUKPT BDK + PVK) | yes — recognised (GP responder) |

`NH` is a response code only (reply to `NG`), not a request command.

### ❌ Not Built (pending)

_None of the catalogued commands remain stubbed._

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

**keyType codes** — A0, BU and the MAC commands all use the standard 3-digit
key type code:

| Command | Type code | Key type |
|---------|-----------|----------|
| A0 / BU | `000` | ZMK |
| A0 / BU | `001` | ZPK |
| A0 / BU | `002` | TPK / PVK (LMK pair 14-15) |
| A0 | `00A` | DATA |
| A0 | `402` | CVK (CVV/CVC) |
| M6 / M8 / VA | `003` | TAK (MAC, terminal) |
| M6 / M8 / VA | `008` | ZAK (MAC, interchange) |

> The semantic key API (`/keys/symmetric`) maps friendly names to these codes.
> `PVK → 002` and `CVK → 402` (previously both `00A`): a key created as `00A` and
> then used by `CW`/`CY` (CVV) or `DA`/`DC`/`DE`/`DG`/`EA` (PIN) fails with parity
> error 10, because it is encrypted under the wrong LMK pair. Create `CVK`/`PVK`
> keys with the correct family code so those ops work.

**Key schemes:**

| Code | Type | Key length |
|------|------|-----------|
| `Z` | Single-length DES | 8 bytes / 16 hex chars |
| `U` | Double-length DES | 16 bytes / 32 hex chars |
| `T` | Triple-length DES | 24 bytes / 48 hex chars |
| `X` / `Y` | Double / triple variant | 32 / 48 hex chars |
| `S` / `R` | **Key block** (3DES / TR-31) | **variable** — length embedded in the token |

For a key block, pass the whole token (scheme char + header + data) as the key
param; `ThalesCmdBuilder` forwards it verbatim and `keyTokenLen()` recovers the
length on parse. Do **not** treat `S` as a fixed-length AES key.

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

`keyType` is the standard 3-digit key type code (same as A0). The gateway encodes
it via the `FF` + Key-Length-Flag + `;` + 3-digit form and derives the length flag
from `scheme` (`U`→double, `T`→triple).

```bash
curl -X POST http://localhost:8090/thales/command/BU \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"keyType":"000","scheme":"U","keyHex":"34FD4D7EFFADEE4EACD1562C18C757DC"}'
```

Params:

| Param | Required | Description |
|-------|----------|-------------|
| `keyType` | yes | 3-digit key type code: `000`=ZMK, `001`=ZPK, `002`=TPK |
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
3. Verify KCVs:    BU keyType=000 (ZMK), BU keyType=001 (ZPK)
4. Export ZPK:     GC zmkHex + zpkHex → zpkUnderZmk  (send to ATM/POS)
5. Import ZPK:     A6 zmkUnderLmk + zpkUnderZmk → zpkUnderLmk (receive from external)
6. Re-export ZPK:  A8 zmkUnderLmk + zpkUnderLmk → zpkUnderZmk
```

> **BU keyType** is the standard 3-digit key type code (`000`=ZMK, `001`=ZPK, `002`=TPK).
> The builder sends it via the `FF` + Key-Length-Flag + `;` + 3-digit form, so the
> length flag is derived from the scheme automatically (`U`→double, `T`→triple).

---

### PIN command bodies (LMK-encrypted PIN path)

These commands operate on a PIN encrypted **under the LMK** — no ZPK and no PIN block.
Account number = the 12 right-most PAN digits excluding the check digit (pass `accountNo`,
or pass `pan` and the gateway derives it).

```bash
# BA — Encrypt a Clear PIN  → returns pinUnderLmk
POST /thales/command/BA
{ "clearPin": "1234", "accountNo": "111111111111", "maxPinLen": "13" }
#   maxPinLen must match the HSM "PIN field length" CS setting (range 5-13).
#   This deployment's HSM = 13 (confirmed: NG decrypt returned PIN + nine 'F's).

# JA — Generate a Random PIN  → returns pinUnderLmk
POST /thales/command/JA
{ "accountNo": "111111111111", "pinLen": "4" }

# NG — Decrypt an Encrypted PIN  → returns clearPin + referenceNumber
POST /thales/command/NG
{ "accountNo": "111111111111", "pinUnderLmk": "<BA/JA output>" }
```

`DE`, `DG`, `JG` consume the `pinUnderLmk` produced by `BA`/`JA`.

### MAC command bodies (M6 / M8 / VA)

`keyType` is `003` (TAK) or `008` (ZAK). The body carries a **MAC Size** field
(`macSize`: `0`=8-hex MAC, `1`=16-hex) and a 1-char **algorithm** (`1`=ISO 9797-1,
`3`=ISO 9797-3/X9.19, `5`=CBC-MAC, `6`=CMAC). `dataHex` is hex; the gateway sends it raw.

```bash
POST /thales/command/M6
{ "keyType":"003","keyScheme":"U","keyHex":"<TAK under LMK>",
  "macSize":"1","algorithm":"3","padding":"1","dataHex":"0102030405060708090A0B0C0D0E0F10" }
```

> **Note:** the "generate random value" command is `N0`, not `OA` (`OA` = Print PIN Mailer).
> A `/thales/command/N0` endpoint is not yet wired.

### Data encrypt / decrypt (M0 / M2)

Message Length is **4 hex digits = byte count** and the data block is sent as **raw
binary** (Input Format `0`); Output Format `1` makes the M1/M3 response hex. Pass the
plaintext/ciphertext as hex — the gateway decodes it to binary on the wire.

```bash
POST /thales/command/M0          # encrypt → ciphertextHex
{ "keyType":"00A","keyScheme":"U","keyUnderLmk":"<DATA key under LMK>",
  "mode":"00","plaintextHex":"00112233445566778899AABBCCDDEEFF" }

POST /thales/command/M2          # decrypt → plaintext
{ "keyType":"00A","keyScheme":"U","keyUnderLmk":"<DATA key under LMK>",
  "mode":"00","messageHex":"<ciphertext hex>" }
```
For a key-block DATA key set `keyType":"FFF"`, `keyScheme":"S"` and pass the block.

### Verify PIN (DA / EA — IBM offset)

No 3-digit key-type prefix; order is TPK/ZPK then PVK. The decimalization table is the
**encrypted** 16-hex form, PIN validation data uses the `P`+16H form, Offset is 12 hex.

```bash
POST /thales/command/DA
{ "tpkScheme":"S","tpkHex":"<TPK block>", "pvkScheme":"S","pvkHex":"<PVK block>",
  "pinBlock":"<enc PIN block>","pinBlockFormat":"01","checkLen":"6",
  "pan":"<16-digit PAN>","dectab":"<enc dectab 16H>",
  "pinValidationData":"P30000009FFFFFFFF","pinOffset":"085936FFFFFF" }
# err 00 or 02 = PIN verified (02 = PVK double-length warning).
```

---

## Wire Protocol

```
Request frame:  [2-byte BE length][4-byte ASCII header][2-byte cmd][body]
Response frame: [2-byte BE length][4-byte ASCII header][2-byte resp-cmd][2-byte err-code][body]
```

The HSM echoes the 4-byte header. Set it via `sentinel.thales.header`; the live
deployment uses **`RSM5`** (`0000` also works). Error code `00` = success
(`02` is a non-fatal warning on some PIN commands). All codes in `ThalesErrorCode.java`.

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
