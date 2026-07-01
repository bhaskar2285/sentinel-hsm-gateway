# Sentinel HSM Gateway — Remote API Testing

REST gateway over the Thales payShield. Another machine drives HSM commands over HTTP/JSON.
Curls below are the operations **confirmed working live** (errCode `00`).

## 1. Connect

| | |
|---|---|
| Base URL | `http://<HOST-IP>:8090/api/v1` |
| Port | `8090` (binds all interfaces) |
| Transport | **plain HTTP** (TLS off — set `TLS_ENABLED=true` before exposing beyond a trusted LAN/VPN) |
| Auth | session token: `POST /auth/login` → `Authorization: Bearer <token>` on every call |
| Tenant | optional `X-Bank-Id: <id>` scopes keys to a bank; omit = all (admin) |

Swap `<HOST-IP>` for the gateway host's reachable address (LAN/VPN). Keep it off the public internet unless TLS is enabled.

## 2. Working operations — 8 confirmed (Linux/macOS bash)

```bash
GW=http://<HOST-IP>:8090/api/v1

# 0) login -> token
TOKEN=$(curl -s -X POST $GW/auth/login -H 'Content-Type: application/json' \
  -d '{"loginname":"admin","password":"sentinel123"}' | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])')

# helper: list keys to get the IDs used below (note keyType + algo)
curl -s $GW/keys -H "Authorization: Bearer $TOKEN"

# 1) Key Check Value (BU)   — any CVK/KBPK key
curl -s -X POST $GW/crypto/key/check-value -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"keyId":"<CVK_OR_KBPK_ID>"}'

# 2) MAC generate (M6)      — needs a TAK (key type 003, 3DES)
curl -s -X POST $GW/crypto/mac/generate -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"keyId":"<TAK_ID>","dataHex":"31323334","algorithm":"3","mode":"0"}'

# 3) MAC verify (M8)        — same key + the mac from step 2
curl -s -X POST $GW/crypto/mac/verify -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"keyId":"<TAK_ID>","dataHex":"31323334","algorithm":"3","mode":"0","mac":"<MAC>"}'

# 4) CVV generate (CW)      — key-block CVK (scheme S) works; returns 3-digit cvv
curl -s -X POST $GW/crypto/cvv/generate -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"cvkaKeyId":"<CVK_ID>","cvkbKeyId":"<CVK_ID>","pan":"4000001234560000","expDate":"2512","serviceCode":"201"}'

# 5) CVV verify (CY)        — same params + the cvv from step 4
curl -s -X POST $GW/crypto/cvv/verify -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"cvkaKeyId":"<CVK_ID>","cvkbKeyId":"<CVK_ID>","pan":"4000001234560000","expDate":"2512","serviceCode":"201","cvv":"<CVV>"}'

# 6) Encrypt data (M0)      — DATA key (3DES), ECB mode 00, hex multiple of 16
curl -s -X POST $GW/crypto/encrypt -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"keyId":"<DATA_ID>","plaintextHex":"00010203040506070001020304050607","mode":"00","iv":"0000000000000000","keyType":"00A"}'

# 7) Decrypt data (M2)      — same key + ciphertext from step 6
curl -s -X POST $GW/crypto/decrypt -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"keyId":"<DATA_ID>","ciphertextHex":"<CIPHERTEXT>","mode":"00","iv":"0000000000000000"}'

# 8) PIN generate           — random PIN under LMK (no key needed)
curl -s -X POST $GW/crypto/pin/generate -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"pan":"400000123456","pinLen":"04"}'
```

Plus **key generation** (`POST /keys/symmetric`, `keyScheme` `U`=3DES variant or `S`=Key Block LMK) works for all key types.

## 3. Windows (PowerShell)

```powershell
$GW = "http://<HOST-IP>:8090/api/v1"
$login = Invoke-RestMethod -Method Post -Uri "$GW/auth/login" -ContentType 'application/json' `
  -Body '{"loginname":"admin","password":"sentinel123"}'
$H = @{ Authorization = "Bearer $($login.token)" }

# CVV generate (key-block CVK)
$b = @{ cvkaKeyId="<CVK_ID>"; cvkbKeyId="<CVK_ID>"; pan="4000001234560000"; expDate="2512"; serviceCode="201" } | ConvertTo-Json
Invoke-RestMethod -Method Post -Uri "$GW/crypto/cvv/generate" -Headers $H -ContentType 'application/json' -Body $b

# MAC generate (TAK type 003)
$b = @{ keyId="<TAK_ID>"; dataHex="31323334"; algorithm="3"; mode="0" } | ConvertTo-Json
Invoke-RestMethod -Method Post -Uri "$GW/crypto/mac/generate" -Headers $H -ContentType 'application/json' -Body $b
```

## 4. Postman

1. `POST {{GW}}/auth/login` raw-JSON `{"loginname":"admin","password":"sentinel123"}`.
2. Tests tab: `pm.environment.set("token", pm.response.json().token)`.
3. Other requests → Authorization → Bearer Token → `{{token}}`.
4. Env vars: `GW=http://<HOST-IP>:8090/api/v1`, `token`.

## 5. Status — what runs today

**Working (8):** key/check-value · mac/generate · mac/verify · cvv/generate · cvv/verify · encrypt · decrypt · pin/generate. (+ key generation A0, variant & key-block.)

**Not working / needs work:**
- `hmac/generate`,`hmac/verify` (LQ/LS) — errCode 15 for all keys (down).
- `hsm/status`,`hsm/echo`,`random` — errCode 15 (down).
- PIN translate / from-lmk / to-lmk / ibm-offset / pvv / verify-*, `csc/*`, `arqc`, `dcvv` — failed in quick test; most need correct PIN-block / EMV session vectors to classify (not yet confirmed working).

**Key-block (KBPK / scheme-S) note:** the 8 working operations accept **both** 3DES-variant **and** key-block (scheme-S) keys — the gateway emits wire key type `FFF` for key-block tokens. Verified live: MAC, encrypt/decrypt, KCV and CVV all return `00` with key-block keys.

Error codes: `00`=OK · `05`/`28`=invalid key type · `10`=key parity · `11`=no key/PIN · `14`=verify fail · `15`=invalid input data.
