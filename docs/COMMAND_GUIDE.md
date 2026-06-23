# Sentinel Command Guide — per-command usage

How to drive every Thales host command exposed by the Sentinel HSM Gateway,
from both the **console UI** and the **REST API**. The runtime call path is:

```
operator / switching app  ->  Sentinel Gateway API  ->  Thales payShield HSM
```

Each command can be reached two ways:

| Surface | Endpoint | When to use |
|---------|----------|-------------|
| **Semantic** | `POST /api/v1/crypto/**`, `/api/v1/keys/**` | Application & UI code. Typed body; gateway owns the wire layout. |
| **Raw** | `POST /thales/command/{CMD}` | Any command with no semantic endpoint, or to reproduce an exact host trace. Body is a flat map of HSM-native fields. Needs `OP_RAW_CMD`. |

Auth for both: `POST /api/v1/auth/login {loginname,password}` → `{token}`, then
`Authorization: Bearer <token>`. Default console login `admin` / `sentinel123`.

Console pages referenced below:
`KeyCreate`, `KeyCreateSym`, `KeyImport`, `KeyBlock`, `KeyDetail`, `EmvOps`,
`CryptoPlayground`, `CryptoWizard`, `RawConsole`, `Pools`, `Locate`, `Audit`,
`AdminBanks`, `AdminRBAC`.

> A response `errorCode`/`errCode` of `00` means success. Anything else is the
> raw Thales error (e.g. `15` = format/field error, `10` = key parity, `01` =
> verification failed). The Python/shell clients in `integration/` raise on
> any non-`00` code.

---

## 1. Key management

| Cmd | Operation | Semantic endpoint | Frontend page | Key params |
|-----|-----------|-------------------|---------------|------------|
| `A0` | Generate a key (random, under LMK) | `POST /api/v1/keys/symmetric` | KeyCreateSym | `keyType`, `keyScheme`, `algorithm` |
| `EI` | Generate RSA key pair | `POST /api/v1/keys/rsa` | KeyCreate | `keyLength`, `publicExponent` |
| `A2` | Generate & print a key component | raw `A2` | KeyCreate / RawConsole | `keyType`, `keyScheme` |
| `A4` | Form key from encrypted components | `POST /api/v1/crypto/key/form-from-components` | KeyImport | `keyType`, `components[]` |
| `A6` | Import a key under ZMK | `POST /api/v1/keys/import-zmk-wrapped` | KeyImport | `zmkKeyId`, `keyType`, `wrappedKey` |
| `GI` | Import key/data under RSA public key | `POST /api/v1/keys/import-rsa-wrapped` | KeyImport | `keyType`, `wrappedKey`, `padding` |
| `A8` | Export key under ZMK/TMK | `POST /api/v1/crypto/key/export-zmk` · `POST /api/v1/keys/{id}/export` | KeyDetail | `keyId`, `zmkKeyId` |
| `GK` | Export key under RSA public key | `POST /api/v1/keys/{id}/export` | KeyDetail | `keyId`, `publicKey` |
| `GC` | Export ZPK under ZMK (LMK→ZMK) | `POST /api/v1/crypto/key/export-zmk` | KeyDetail | `zpkKeyId`, `zmkKeyId` |
| `B4` | Form key block (TR-31 / X9.143 wrap) | raw `B4` | KeyBlock | `keyType`, `wrappingKey`, `header` |
| `BW` | Translate keys old/new LMK + migrate type | raw `BW` | KeyBlock | `keyType`, `key`, `newKeyType` |
| `BU` | Generate key check value (KCV) | `POST /api/v1/crypto/key/check-value` | KeyDetail / KeyCreateSym | `keyType`, `keyScheme`, `key` |
| `HC` | Generate TPK | `POST /api/v1/crypto/key/generate-tpk` | KeyCreateSym | `keyScheme` |
| `IA` | Generate ZPK | `POST /api/v1/crypto/key/generate-zpk` | KeyCreateSym | `keyScheme` |

List keys: `GET /api/v1/keys` (Locate page). Component generate:
`POST /api/v1/crypto/key/component/generate`.

---

## 2. PIN operations

| Cmd | Operation | Semantic endpoint | Frontend page | Key params |
|-----|-----------|-------------------|---------------|------------|
| `JA` | Generate a random PIN | `POST /api/v1/crypto/pin/generate` | CryptoWizard | `pan`, `pinLength` |
| `DE` | Generate IBM PIN offset | `POST /api/v1/crypto/pin/ibm-offset` | CryptoWizard | `pvkKeyId`, `pan`, `pin`, `dectab` |
| `DG` | Generate ABA PVV | `POST /api/v1/crypto/pin/pvv` | CryptoWizard | `pvkKeyId`, `pan`, `pin`, `pvki` |
| `BA` | Encrypt clear PIN under ZPK | `POST /api/v1/crypto/pin/encrypt-clear` | CryptoPlayground | `zpkKeyId`, `pan`, `pin` |
| `EE` | Derive PIN from IBM offset | `POST /api/v1/crypto/pin/derive-ibm` | CryptoWizard | `pvkKeyId`, `pan`, `offset`, `dectab` |
| `NG` | Decrypt encrypted PIN | `POST /api/v1/crypto/pin/decrypt` | CryptoPlayground | `keyId`, `pinBlock`, `pan` |
| `DA` | Verify terminal PIN (IBM 3624) | `POST /api/v1/crypto/pin/verify` | CryptoWizard | `tpkKeyId`, `pvkKeyId`, `pinBlock`, `pan`, `dectab`, `pinOffset` |
| `DC` | Verify terminal PIN (VISA PVV) | `POST /api/v1/crypto/pin/verify-visa` | CryptoWizard | `tpkKeyId`, `pvkKeyId`, `pinBlock`, `pan`, `pvki`, `pvv` |
| `EA` | Verify interchange PIN (IBM 3624) | `POST /api/v1/crypto/pin/verify-interchange-ibm` | CryptoWizard | `zpkKeyId`, `pvkKeyId`, `pinBlock`, `pan` |
| `EC` | Verify interchange PIN (VISA PVV) | `POST /api/v1/crypto/pin/verify-interchange-visa` | CryptoWizard | `zpkKeyId`, `pvkKeyId`, `pinBlock`, `pan`, `pvv` |

### PIN block translation

| Cmd | Operation | Semantic endpoint | Frontend page |
|-----|-----------|-------------------|---------------|
| `CA` | Translate PIN TPK → ZPK/BDK | `POST /api/v1/crypto/pin/translate` | CryptoPlayground |
| `CC` | Translate PIN ZPK → ZPK | `POST /api/v1/crypto/pin/translate-zpk` | CryptoPlayground |
| `JS` | Translate PIN ZPK → ZPK (variant 2) | `POST /api/v1/crypto/pin/translate-zpk2` | RawConsole |
| `JC` | Translate PIN TPK → LMK | `POST /api/v1/crypto/pin/to-lmk` | CryptoPlayground |
| `JE` | Translate PIN ZPK → LMK | `POST /api/v1/crypto/pin/to-lmk` | CryptoPlayground |
| `JG` | Translate PIN LMK → ZPK | `POST /api/v1/crypto/pin/from-lmk` | CryptoPlayground |

Translate params: `srcKeyId`, `dstKeyId`, `pinBlock`, `pinBlockFormat`,
`destFormat`, `pan`.

---

## 3. Card verification values (CVV / CVC / CSC / dCVV)

| Cmd | Operation | Semantic endpoint | Frontend page | Key params |
|-----|-----------|-------------------|---------------|------------|
| `CW` | Generate CVV/CVC/CVV2 | `POST /api/v1/crypto/cvv/generate` | EmvOps | `cvkKeyId`, `pan`, `expiry`, `serviceCode` |
| `CY` | Verify CVV/CVC/CVV2 | `POST /api/v1/crypto/cvv/verify` | EmvOps | `cvkKeyId`, `pan`, `expiry`, `serviceCode`, `cvv` |
| `PM` | Verify dynamic CVV (dCVV CVN17) | `POST /api/v1/crypto/dcvv/verify` | EmvOps | `mkacKeyId`, `pan`, `atc`, `dcvv` |
| `RY` | Calculate / verify CSC (AEVV) | `POST /api/v1/crypto/csc/calculate` · `/csc/verify` | EmvOps | `cscKeyId`, `pan`, `expiry`, `csc` |

> CVK must be created with key family `402` (not `00A`) or generate/verify
> fails with parity error `10`. PVK uses `002`.

---

## 4. EMV / ARQC

| Cmd | Operation | Semantic endpoint | Frontend page | Key params |
|-----|-----------|-------------------|---------------|------------|
| `KQ` | Verify ARQC / generate ARPC | `POST /api/v1/crypto/arqc` | EmvOps | `imkKeyId`, `mode`, `atc`, `arqc`, `transData`, `pan`, `panSeqNo` |
| `KW` | Verify ARQC / generate ARPC (EMV 4.x) | `POST /api/v1/crypto/arqc/emv4` | EmvOps | `imkKeyId`, `atc`, `arqc`, `transData`, `pan`, `cvn` |

ARQC cryptogram-version variants (CVN01/10/14/18/22, AAV/CAVV/AEVV, 3DS) are
parameter variants of `KQ` / `KW` (`mode`, `cvn`) — same endpoints, different
`cvn`/`mode` values selected on EmvOps.

---

## 5. Data encryption & MAC

| Cmd | Operation | Semantic endpoint | Frontend page | Key params |
|-----|-----------|-------------------|---------------|------------|
| `M0` | Encrypt data block | `POST /api/v1/crypto/encrypt` | CryptoPlayground | `keyId`, `plaintextHex`, `mode`, `iv` |
| `M2` | Decrypt data block | `POST /api/v1/crypto/decrypt` | CryptoPlayground | `keyId`, `ciphertextHex`, `mode`, `iv` |
| `M6` | Generate MAC | `POST /api/v1/crypto/mac/generate` | CryptoPlayground | `keyId`, `message`, `macMode` |
| `M8` | Verify MAC | `POST /api/v1/crypto/mac/verify` | CryptoPlayground | `keyId`, `message`, `mac` |
| `VA` | Verify MAC (full-format variant) | `POST /api/v1/crypto/mac/verify-alt` | RawConsole | `keyId`, `message`, `mac` |
| `LQ` | Generate HMAC (SPA2 AAV) | `POST /api/v1/crypto/hmac/generate` | CryptoPlayground | `keyId`, `message`, `hashAlgo` |
| `LS` | Verify HMAC (SPA2 AAV) | `POST /api/v1/crypto/hmac/verify` | CryptoPlayground | `keyId`, `message`, `hmac` |

> `encrypt`/`decrypt` default to CBC (`mode:"01"`, needs `iv`). Use `mode:"00"`
> (ECB) for a no-IV round-trip. `decrypt` returns `plaintextHex` as hex
> (`outputFormat:"1"`).

---

## 6. Diagnostics & utility

| Cmd | Operation | Semantic endpoint | Frontend page |
|-----|-----------|-------------------|---------------|
| `B2` | Echo / loopback | `POST /api/v1/crypto/hsm/echo` | RawConsole |
| `NO` | HSM status (echo) | `GET /api/v1/crypto/hsm/status` | Pools / RawConsole |
| `NC` | Network connectivity check | raw `NC` | Pools |
| `OA` | Generate random data | `POST /api/v1/crypto/random` | CryptoPlayground |

HSM node + pool config (host/port/enable) lives behind `/api/v1/hsms` and
`/api/v1/pools` — managed on the **Pools** page. A `HealthProbeService` pings
enabled nodes every 15s; the dispatcher routes only to `health=UP` nodes.

---

## 7. Specialised / legacy commands

Real payShield functions (not the old "legacy PIN" placeholders). These are
raw-only and several need hardware (printer / Key-Change LMKs / DUKPT vectors)
not present in a sim, so they validate command recognition rather than full
crypto here.

| Cmd | Operation | Reach | Frontend page | Notes |
|-----|-----------|-------|---------------|-------|
| `PA` | Load formatting data to HSM | raw `PA` | RawConsole | Printer formatting table |
| `PC` | Load additional formatting data | raw `PC` | RawConsole | Extends `PA` |
| `PE` | Print PIN / solicitation data | raw `PE` | RawConsole | Needs USB printer |
| `BG` | Translate PIN old-LMK → new-LMK | raw `BG` | RawConsole | Needs Key-Change LMKs |
| `G0` | DUKPT PIN translate (→ ZPK/DUKPT) | raw `G0` | RawConsole | Needs BDK + KSN |
| `GO` | DUKPT PIN verify (BDK + PVK) | raw `GO` | RawConsole | Needs BDK + KSN + PVK |

---

## Worked examples

**Generate a ZPK (semantic):**
```bash
curl -s -X POST http://localhost:8090/api/v1/keys/symmetric \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"keyType":"001","keyScheme":"U","algorithm":"3DES"}'
```

**Generate a CVV (semantic):**
```bash
curl -s -X POST http://localhost:8090/api/v1/crypto/cvv/generate \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"cvkKeyId":"<id>","pan":"4111111111111111","expiry":"2512","serviceCode":"201"}'
```

**Generate a MAC via the raw passthrough:**
```bash
curl -s -X POST http://localhost:8090/thales/command/M6 \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"keyType":"008","keyScheme":"U","key":"<zak>","message":"48656C6C6F"}'
```

**Python client:**
```python
from sentinel_client import SentinelClient
sc = SentinelClient("http://localhost:8090", "admin", "sentinel123"); sc.login()
sc.cvv_generate(cvkKeyId=kid, pan="4111111111111111", expiry="2512", serviceCode="201")
sc.raw("M6", {"keyType":"008","keyScheme":"U","key":zak,"message":"48656C6C6F"})
```

See `integration/sentinel_client.py` and `integration/sentinel_client.sh` for
the full switching-app integration clients.
