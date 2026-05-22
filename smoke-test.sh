#!/usr/bin/env bash
# Sentinel HSM Gateway — end-to-end smoke test.
#
# Walks the full happy path: login → ZMK gen → ZPK gen under ZMK
# → encrypt → decrypt → round-trip assert.
#
# Requires: curl, jq.
# Defaults assume gateway on host port 8090 (per docker compose) and
# the seeded admin login (admin / sentinel123).
#
# Override via env:
#   GW=http://1.2.3.4:8090 BANK=2 BRANCH=20 ./smoke-test.sh
#
set -euo pipefail

GW="${GW:-http://localhost:8090}"
BANK="${BANK:-1}"
BRANCH="${BRANCH:-10}"
USER="${SENTINEL_USER:-admin}"
PASS="${SENTINEL_PASS:-sentinel123}"

PLAINTEXT_HEX="48656C6C6F2C2073656E74696E656C21"   # "Hello, sentinel!"
IV_3DES_HEX="0000000000000000"                     # 16 hex = 8 bytes (3DES)

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
blue()  { printf '\033[34m%s\033[0m\n' "$*"; }

step() { printf '\n\033[1m▶ %s\033[0m\n' "$*"; }

need() { command -v "$1" >/dev/null || { red "missing dep: $1"; exit 1; }; }
need curl
need jq

# --------------------------------------------------------------------
step "1. Login as $USER → grab JWT"
LOGIN_BODY=$(jq -nc --arg u "$USER" --arg p "$PASS" '{loginname:$u,password:$p}')
LOGIN_RES=$(curl -sX POST "$GW/api/v1/auth/login" \
  -H 'Content-Type: application/json' \
  -d "$LOGIN_BODY")

TOKEN=$(echo "$LOGIN_RES" | jq -r '.token // empty')
if [[ -z "$TOKEN" ]]; then
  red "Login failed:"; echo "$LOGIN_RES" | jq .
  exit 1
fi
blue "TOKEN=${TOKEN:0:24}…"

H_AUTH="Authorization: Bearer $TOKEN"

# --------------------------------------------------------------------
step "2. Generate ZMK (Zone Master Key, mode 0 — fresh under LMK)"
ZMK_RES=$(curl -sX POST "$GW/api/v1/keys/symmetric" \
  -H "$H_AUTH" -H 'Content-Type: application/json' \
  -H "X-Bank-Id:$BANK" -H "X-Branch-Id:$BRANCH" \
  -d "{\"label\":\"smoke-zmk-$$\",\"keyType\":\"ZMK\",\"keyScheme\":\"U\",\"mode\":\"0\"}")

ZMK_ID=$(echo "$ZMK_RES" | jq -r '.keyId // empty')
[[ -n "$ZMK_ID" ]] || { red "ZMK create failed:"; echo "$ZMK_RES" | jq .; exit 1; }
blue "ZMK_ID=$ZMK_ID"

# --------------------------------------------------------------------
step "3. Generate ZPK under ZMK (mode 1 — wrapped under ZMK)"
ZPK_BODY=$(jq -nc --arg z "$ZMK_ID" --arg lbl "smoke-zpk-$$" \
  '{label:$lbl,keyType:"ZPK",keyScheme:"U",mode:"1",zmkKeyId:$z,outScheme:"U"}')
ZPK_RES=$(curl -sX POST "$GW/api/v1/keys/symmetric" \
  -H "$H_AUTH" -H 'Content-Type: application/json' \
  -H "X-Bank-Id:$BANK" -H "X-Branch-Id:$BRANCH" \
  -d "$ZPK_BODY")

ZPK_ID=$(echo "$ZPK_RES" | jq -r '.keyId // empty')
[[ -n "$ZPK_ID" ]] || { red "ZPK create failed:"; echo "$ZPK_RES" | jq .; exit 1; }
blue "ZPK_ID=$ZPK_ID"

# --------------------------------------------------------------------
step "4. Encrypt plaintext under ZPK"
ENC_BODY=$(jq -nc --arg k "$ZPK_ID" --arg pt "$PLAINTEXT_HEX" --arg iv "$IV_3DES_HEX" \
  '{keyId:$k,plaintextHex:$pt,ivHex:$iv}')
ENC_RES=$(curl -sX POST "$GW/api/v1/crypto/encrypt" \
  -H "$H_AUTH" -H 'Content-Type: application/json' \
  -d "$ENC_BODY")

CT=$(echo "$ENC_RES" | jq -r '.ciphertextHex // empty')
[[ -n "$CT" ]] || { red "Encrypt failed:"; echo "$ENC_RES" | jq .; exit 1; }
blue "plaintext  = $PLAINTEXT_HEX"
blue "ciphertext = $CT"

# --------------------------------------------------------------------
step "5. Decrypt ciphertext back under ZPK"
DEC_BODY=$(jq -nc --arg k "$ZPK_ID" --arg ct "$CT" --arg iv "$IV_3DES_HEX" \
  '{keyId:$k,ciphertextHex:$ct,ivHex:$iv}')
DEC_RES=$(curl -sX POST "$GW/api/v1/crypto/decrypt" \
  -H "$H_AUTH" -H 'Content-Type: application/json' \
  -d "$DEC_BODY")

PT=$(echo "$DEC_RES" | jq -r '.plaintextHex // empty')
[[ -n "$PT" ]] || { red "Decrypt failed:"; echo "$DEC_RES" | jq .; exit 1; }
blue "round-trip = $PT"

# --------------------------------------------------------------------
step "6. List keys under tenant bank=$BANK"
COUNT=$(curl -s "$GW/api/v1/keys" \
  -H "$H_AUTH" -H "X-Bank-Id:$BANK" -H "X-Branch-Id:$BRANCH" | jq 'length')
blue "tenant key count = $COUNT"

# --------------------------------------------------------------------
echo
if [[ "${PT^^}" == "${PLAINTEXT_HEX^^}" ]]; then
  green "✓ round-trip OK — gateway end-to-end healthy"
  exit 0
else
  red "✗ round-trip mismatch"
  red "   expected: $PLAINTEXT_HEX"
  red "   got:      $PT"
  exit 2
fi
