#!/usr/bin/env bash
#
# Sentinel HSM Gateway - curl-based switching integration helper
# ==============================================================
# Call path:  switching app -> Sentinel Gateway API -> Thales payShield HSM
#
# Drop-in shell equivalent of integration/sentinel_client.py for switches that
# don't run Python. Logs in once, caches the bearer token, then exposes two
# verbs:
#
#   raw  <CMD>  <json>     POST /thales/command/<CMD>      (generic passthrough)
#   api  <PATH> <json>     POST <PATH>                     (semantic endpoint)
#   get  <PATH>            GET  <PATH>
#
# Requires: bash, curl, and jq.
#
# Examples:
#   ./sentinel_client.sh get  /api/v1/crypto/hsm/status
#   ./sentinel_client.sh api  /api/v1/crypto/hsm/echo   '{"data":"DEADBEEF"}'
#   ./sentinel_client.sh api  /api/v1/crypto/encrypt    '{"keyId":"...","plaintextHex":"00112233...","mode":"00"}'
#   ./sentinel_client.sh raw  M6                         '{"keyType":"008","keyScheme":"U","key":"...","message":"..."}'
#
# Override via env: BASE_URL, SENTINEL_USER, SENTINEL_PASS.

set -euo pipefail

BASE_URL="${BASE_URL:-http://localhost:8090}"
SENTINEL_USER="${SENTINEL_USER:-admin}"
SENTINEL_PASS="${SENTINEL_PASS:-sentinel123}"
TOKEN_FILE="${TOKEN_FILE:-/tmp/.sentinel_token}"

die() { echo "ERROR: $*" >&2; exit 1; }
command -v curl >/dev/null || die "curl not found"
command -v jq   >/dev/null || die "jq not found"

login() {
  local resp token
  resp="$(curl -fsS -X POST "$BASE_URL/api/v1/auth/login" \
            -H 'Content-Type: application/json' \
            -d "$(jq -n --arg u "$SENTINEL_USER" --arg p "$SENTINEL_PASS" \
                  '{loginname:$u, password:$p}')")" \
    || die "login request failed"
  token="$(echo "$resp" | jq -r '.token // empty')"
  [ -n "$token" ] || die "login rejected: $(echo "$resp" | jq -r '.reason // "unknown"')"
  printf '%s' "$token" > "$TOKEN_FILE"
  echo "$token"
}

token() {
  if [ -s "$TOKEN_FILE" ]; then cat "$TOKEN_FILE"; else login; fi
}

# Re-login once on 401, so a stale cached token self-heals.
call() {
  local method="$1" path="$2" body="${3:-}"
  local tok http out
  tok="$(token)"
  local args=(-sS -o /tmp/.sentinel_out -w '%{http_code}'
              -X "$method" "$BASE_URL$path"
              -H "Authorization: Bearer $tok")
  if [ -n "$body" ]; then args+=(-H 'Content-Type: application/json' -d "$body"); fi
  http="$(curl "${args[@]}")" || die "request failed"
  if [ "$http" = "401" ]; then
    rm -f "$TOKEN_FILE"; tok="$(login)"
    args=(-sS -o /tmp/.sentinel_out -w '%{http_code}'
          -X "$method" "$BASE_URL$path" -H "Authorization: Bearer $tok")
    if [ -n "$body" ]; then args+=(-H 'Content-Type: application/json' -d "$body"); fi
    http="$(curl "${args[@]}")"
  fi
  out="$(cat /tmp/.sentinel_out)"; rm -f /tmp/.sentinel_out
  if [ "$http" -ge 400 ]; then
    echo "$out" | jq . 2>/dev/null || echo "$out"
    die "HTTP $http on $path"
  fi
  echo "$out" | jq . 2>/dev/null || echo "$out"
}

usage() {
  sed -n '2,30p' "$0"
  exit 1
}

[ $# -ge 1 ] || usage
verb="$1"; shift
case "$verb" in
  login) login >/dev/null && echo "ok" ;;
  get)   [ $# -ge 1 ] || usage; call GET "$1" ;;
  api)   [ $# -ge 1 ] || usage; call POST "$1" "${2:-{}}" ;;
  raw)   [ $# -ge 1 ] || usage; call POST "/thales/command/${1^^}" "${2:-{}}" ;;
  *)     usage ;;
esac
