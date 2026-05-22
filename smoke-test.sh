#!/usr/bin/env bash
# Sentinel HSM Gateway — end-to-end smoke test.
#
# Walks the full happy path: login → ZMK gen → ZPK gen under ZMK
# → encrypt → decrypt → round-trip assert.
#
# Each step prints the key UUIDs used + a /keys/<id> probe so you can
# trace which DB row participated where.
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

red()    { printf '\033[31m%s\033[0m\n' "$*"; }
green()  { printf '\033[32m%s\033[0m\n' "$*"; }
blue()   { printf '\033[34m%s\033[0m\n' "$*"; }
yellow() { printf '\033[33m%s\033[0m\n' "$*"; }
dim()    { printf '\033[2m%s\033[0m\n' "$*"; }

step() { printf '\n\033[1m▶ %s\033[0m\n' "$*"; }

need() { command -v "$1" >/dev/null || { red "missing dep: $1"; exit 1; }; }
need curl
need jq

# probe_key  <label>  <uuid>
# Re-fetches a key from the gateway and prints UUID, label, type, scheme,
# KCV, bank, branch. Lets you confirm which DB record is being touched.
probe_key() {
  local label="$1"; local id="$2"
  local body
  body=$(curl -s "$GW/api/v1/keys/$id" -H "$H_AUTH")
  printf '   \033[36m%-12s\033[0m %s\n' "$label keyId:" "$id"
  echo "$body" | jq -r '
    "                 label   : " + (.label // "—"),
    "                 type    : " + (.keyType // "—"),
    "                 algo    : " + (.algo // "—") + " / " + ((.keyLengthBits // 0)|tostring) + " bits",
    "                 kcv     : " + (.kcv // "—"),
    "                 bank    : " + ((.bankRecId // "—") | tostring),
    "                 branch  : " + ((.branchRecId // "—") | tostring),
    "                 status  : " + (.status // "—")
  '
}

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
step "1b. Ensure a branch exists under bank=$BANK (FK target for hsm_key)"
BRANCHES_RES=$(curl -s "$GW/api/v1/admin/banks/$BANK/branches" -H "$H_AUTH")
FIRST_BRANCH=$(echo "$BRANCHES_RES" | jq -r 'if (type == "array" and length > 0) then .[0].recId else empty end')

if [[ -z "$FIRST_BRANCH" ]]; then
  yellow "no branches; bootstrapping one under bank=$BANK"
  CREATE_RES=$(curl -sX POST "$GW/api/v1/admin/banks/$BANK/branches" \
    -H "$H_AUTH" -H 'Content-Type: application/json' \
    -d '{"code":"HQ","name":"Smoke Test Branch","city":"Bangalore","countryIso2":"IN"}')
  FIRST_BRANCH=$(echo "$CREATE_RES" | jq -r '.recId // empty')
  [[ -n "$FIRST_BRANCH" ]] || { red "branch create failed:"; echo "$CREATE_RES" | jq .; exit 1; }
fi
BRANCH="$FIRST_BRANCH"
blue "BANK=$BANK  BRANCH=$BRANCH  (tenant headers attached to every key write)"

# --------------------------------------------------------------------
step "2. Generate ZMK (A0 mode 0 — fresh random key, sealed under LMK only)"
ZMK_LABEL="smoke-zmk-$$"
dim "POST /api/v1/keys/symmetric  X-Bank-Id:$BANK  X-Branch-Id:$BRANCH"
dim "  body: {label:\"$ZMK_LABEL\", keyType:ZMK, keyScheme:U, mode:0}"
ZMK_RES=$(curl -sX POST "$GW/api/v1/keys/symmetric" \
  -H "$H_AUTH" -H 'Content-Type: application/json' \
  -H "X-Bank-Id:$BANK" -H "X-Branch-Id:$BRANCH" \
  -d "{\"label\":\"$ZMK_LABEL\",\"keyType\":\"ZMK\",\"keyScheme\":\"U\",\"mode\":\"0\"}")

ZMK_ID=$(echo "$ZMK_RES" | jq -r '.keyId // empty')
[[ -n "$ZMK_ID" ]] || { red "ZMK create failed:"; echo "$ZMK_RES" | jq .; exit 1; }
probe_key "ZMK" "$ZMK_ID"

# --------------------------------------------------------------------
step "3. Generate ZPK under ZMK (A0 mode 1 — wraps result under above ZMK)"
ZPK_LABEL="smoke-zpk-$$"
dim "POST /api/v1/keys/symmetric  X-Bank-Id:$BANK  X-Branch-Id:$BRANCH"
dim "  body: {label:\"$ZPK_LABEL\", keyType:ZPK, keyScheme:U, mode:1,"
dim "         zmkKeyId:\"$ZMK_ID\", outScheme:U}"
ZPK_BODY=$(jq -nc --arg z "$ZMK_ID" --arg lbl "$ZPK_LABEL" \
  '{label:$lbl,keyType:"ZPK",keyScheme:"U",mode:"1",zmkKeyId:$z,outScheme:"U"}')
ZPK_RES=$(curl -sX POST "$GW/api/v1/keys/symmetric" \
  -H "$H_AUTH" -H 'Content-Type: application/json' \
  -H "X-Bank-Id:$BANK" -H "X-Branch-Id:$BRANCH" \
  -d "$ZPK_BODY")

ZPK_ID=$(echo "$ZPK_RES" | jq -r '.keyId // empty')
KEY_UNDER_ZMK=$(echo "$ZPK_RES" | jq -r '.keyUnderZmk // empty')
[[ -n "$ZPK_ID" ]] || { red "ZPK create failed:"; echo "$ZPK_RES" | jq .; exit 1; }
probe_key "ZPK" "$ZPK_ID"
if [[ -n "$KEY_UNDER_ZMK" ]]; then
  dim "                 ZPK_under_ZMK (export-form): $KEY_UNDER_ZMK"
fi

# --------------------------------------------------------------------
step "4. Encrypt plaintext under ZPK (M0 CBC)"
dim "POST /api/v1/crypto/encrypt"
dim "  body: {keyId:\"$ZPK_ID\", plaintextHex:\"$PLAINTEXT_HEX\", iv:\"$IV_3DES_HEX\"}"
ENC_BODY=$(jq -nc --arg k "$ZPK_ID" --arg pt "$PLAINTEXT_HEX" --arg iv "$IV_3DES_HEX" \
  '{keyId:$k,plaintextHex:$pt,iv:$iv}')
ENC_RES=$(curl -sX POST "$GW/api/v1/crypto/encrypt" \
  -H "$H_AUTH" -H 'Content-Type: application/json' \
  -d "$ENC_BODY")

CT=$(echo "$ENC_RES" | jq -r '.ciphertextHex // empty')
[[ -n "$CT" ]] || { red "Encrypt failed:"; echo "$ENC_RES" | jq .; exit 1; }
printf '   \033[36m%-12s\033[0m %s\n' "ENCRYPT keyId:" "$ZPK_ID"
printf '   \033[36m%-12s\033[0m %s\n' "plaintext:"     "$PLAINTEXT_HEX"
printf '   \033[36m%-12s\033[0m %s\n' "iv:"            "$IV_3DES_HEX"
printf '   \033[36m%-12s\033[0m %s\n' "ciphertext:"    "$CT"

# --------------------------------------------------------------------
step "5. Decrypt ciphertext back under SAME ZPK (M2 CBC)"
dim "POST /api/v1/crypto/decrypt"
dim "  body: {keyId:\"$ZPK_ID\", ciphertextHex:\"$CT\", iv:\"$IV_3DES_HEX\"}"
DEC_BODY=$(jq -nc --arg k "$ZPK_ID" --arg ct "$CT" --arg iv "$IV_3DES_HEX" \
  '{keyId:$k,ciphertextHex:$ct,iv:$iv}')
DEC_RES=$(curl -sX POST "$GW/api/v1/crypto/decrypt" \
  -H "$H_AUTH" -H 'Content-Type: application/json' \
  -d "$DEC_BODY")

PT=$(echo "$DEC_RES" | jq -r '.plaintextHex // empty')
[[ -n "$PT" ]] || { red "Decrypt failed:"; echo "$DEC_RES" | jq .; exit 1; }
printf '   \033[36m%-12s\033[0m %s\n' "DECRYPT keyId:" "$ZPK_ID"
printf '   \033[36m%-12s\033[0m %s\n' "ciphertext:"    "$CT"
printf '   \033[36m%-12s\033[0m %s\n' "iv:"            "$IV_3DES_HEX"
printf '   \033[36m%-12s\033[0m %s\n' "round-trip:"    "$PT"

# --------------------------------------------------------------------
step "6. Tenant scope check — list /keys under X-Bank-Id=$BANK"
COUNT=$(curl -s "$GW/api/v1/keys" \
  -H "$H_AUTH" -H "X-Bank-Id:$BANK" -H "X-Branch-Id:$BRANCH" | jq 'length')
blue "tenant key count = $COUNT"
dim "  (both ZMK and ZPK above should be inside this set)"

# --------------------------------------------------------------------
echo
echo "──────────────────────────────────────────────"
echo " Key chain used in this run"
echo "──────────────────────────────────────────────"
echo "  ZMK_ID = $ZMK_ID"
echo "  ZPK_ID = $ZPK_ID   (generated under ZMK_ID, used for both encrypt & decrypt)"
echo "──────────────────────────────────────────────"

if [[ "${PT^^}" == "${PLAINTEXT_HEX^^}" ]]; then
  green "✓ round-trip OK — same ZPK round-tripped plaintext, end-to-end healthy"
  exit 0
else
  red "✗ round-trip mismatch"
  red "   expected: $PLAINTEXT_HEX"
  red "   got:      $PT"
  exit 2
fi
