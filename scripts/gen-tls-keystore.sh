#!/usr/bin/env bash
#
# Generate a PKCS12 keystore for Sentinel HSM Gateway TLS termination.
# ===================================================================
# TLS is the primary transport protection for the exposed crypto API. Run this
# once to produce certs/sentinel-gateway.p12, then enable TLS via env:
#
#   TLS_ENABLED=true
#   TLS_KEYSTORE=/app/certs/sentinel-gateway.p12
#   TLS_KEYSTORE_PASSWORD=<the password you set below>
#   TLS_KEY_ALIAS=sentinel-gateway
#
# DEV/DEMO: this produces a SELF-SIGNED cert. Clients must pin/trust it.
# PROD: replace with a CA-issued cert (import the CA-signed chain into the same
# alias, or build the PKCS12 from your CA key+chain). Never commit the keystore.
#
# Usage:
#   TLS_KEYSTORE_PASSWORD=change-me ./scripts/gen-tls-keystore.sh [hostname]

set -euo pipefail

HOST="${1:-localhost}"
OUT_DIR="${OUT_DIR:-$(cd "$(dirname "$0")/.." && pwd)/certs}"
ALIAS="${TLS_KEY_ALIAS:-sentinel-gateway}"
PASS="${TLS_KEYSTORE_PASSWORD:?set TLS_KEYSTORE_PASSWORD env var}"
DAYS="${CERT_DAYS:-825}"
KEYSTORE="$OUT_DIR/sentinel-gateway.p12"

command -v keytool >/dev/null || { echo "ERROR: keytool not found (install a JDK)"; exit 1; }

mkdir -p "$OUT_DIR" 2>/dev/null || true
chmod 700 "$OUT_DIR" 2>/dev/null || true

if [ -f "$KEYSTORE" ]; then
  echo "ERROR: $KEYSTORE already exists. Remove it first to regenerate." >&2
  exit 1
fi

keytool -genkeypair \
  -alias "$ALIAS" \
  -keyalg RSA -keysize 3072 \
  -sigalg SHA256withRSA \
  -validity "$DAYS" \
  -storetype PKCS12 \
  -keystore "$KEYSTORE" \
  -storepass "$PASS" \
  -dname "CN=$HOST, OU=Sentinel HSM Gateway, O=ISC" \
  -ext "san=dns:$HOST,dns:localhost,ip:127.0.0.1"

chmod 600 "$KEYSTORE"
echo "Wrote $KEYSTORE (alias=$ALIAS, host=$HOST, valid ${DAYS}d)."
echo "Export the public cert for client trust-pinning:"
echo "  keytool -exportcert -rfc -alias $ALIAS -keystore $KEYSTORE -storepass '<pass>' -file $OUT_DIR/sentinel-gateway.crt"
