#!/usr/bin/env bash
# Initialize the ProtectToolkit-C software-emulation token on Slot 0 so SunPKCS11
# can C_Login as the normal user. Idempotent-ish: if the token is already
# initialized this re-init is skipped (re-init would lock an in-use token).
#
# PINs from env (dev defaults):
#   ADMIN_SO_PIN  - HSM admin Security-Officer PIN (default Password1!)
#   USER_PIN      - Slot 0 token user PIN used by the gateway (default sentinel123)
#   TOKEN_LABEL   - Slot 0 token label (default SENTINEL)
set -u
export CPROVDIR=/opt/safenet/protecttoolkit7/ptk
export PATH="$CPROVDIR/bin:$PATH"
export LD_LIBRARY_PATH="$CPROVDIR/lib"

ADMIN_SO_PIN="${ADMIN_SO_PIN:-Password1!}"
USER_PIN="${USER_PIN:-sentinel123}"
TOKEN_LABEL="${TOKEN_LABEL:-SENTINEL}"

# 1. Set the HSM Admin SO PIN on first contact (ctconf prompts twice; loops on EOF).
yes "$ADMIN_SO_PIN" | ctconf >/dev/null 2>&1 || true

# 2. Initialize the Slot 0 user token (-l label, -o SO PIN, -u user PIN) — one step.
#    Skip if already initialized (TOKEN-INIT flag present) to avoid locking it.
if ctstat 2>/dev/null | sed -n '/Slot ID 0/,/Slot ID 1/p' | grep -q "Label *: *$TOKEN_LABEL"; then
    echo "init-token: Slot 0 token '$TOKEN_LABEL' already initialized — skipping."
else
    echo "init-token: initializing Slot 0 token '$TOKEN_LABEL'..."
    ctkmu t -s0 -l "$TOKEN_LABEL" -o "$ADMIN_SO_PIN" -u "$USER_PIN" 2>&1 | grep -viE 'pin|confirm' || true
fi

# 3. Confirm a user login works.
echo "init-token: verifying user login on Slot 0..."
ctkmu l -s0 -u "$USER_PIN" 2>&1 | grep -iE 'Label|Objects|Could not' || true
