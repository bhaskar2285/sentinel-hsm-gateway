#!/usr/bin/env bash
# =============================================================================
# Sentinel HSM Gateway — API Test Script
# All 43 Thales command endpoints
# =============================================================================
# Usage:
#   chmod +x SENTINEL_API_TESTS.sh
#   ./SENTINEL_API_TESTS.sh
#
# Prerequisites:
#   - Gateway running on http://localhost:8090
#   - At least one UP HSM node (call HSM_STATUS first)
#   - Replace UUIDs in KEYS section with actual key IDs from your vault
# =============================================================================

BASE="http://localhost:8090/api/v1"
H="Content-Type: application/json"

# --- Auth (prod mode: set JWT; dev mode: leave empty) ---
JWT=""
AUTH_HEADER() { [ -n "$JWT" ] && echo "-H \"Authorization: Bearer $JWT\"" || echo ""; }

pp() { python3 -m json.tool 2>/dev/null || cat; }

# =============================================================================
# REPLACE THESE with real key UUIDs from GET /api/v1/keys
# =============================================================================
KEY_RSA=""           # RSA key UUID
KEY_ZMK=""           # ZMK key UUID
KEY_ZPK=""           # ZPK key UUID
KEY_TPK=""           # TPK key UUID
KEY_PVK=""           # PVK key UUID
KEY_CVK_A=""         # CVK-A key UUID
KEY_CVK_B=""         # CVK-B key UUID
KEY_3DES=""          # 3DES data key UUID
KEY_KBPK=""          # KBPK/TR-31 key UUID
KEY_IMK=""           # IMK (EMV) key UUID
KEY_MAC=""           # MAC key UUID
KEY_HMAC=""          # HMAC key UUID
KEY_TPK2=""          # Second TPK (for translate)
KEY_ZPK_DST=""       # Destination ZPK (for PIN translate)

echo "=== Sentinel HSM Gateway — Full API Test ==="
echo "Base: $BASE"
echo ""

# =============================================================================
# 1. HSM STATUS — NO/ND
# =============================================================================
echo "--- 1. HSM Status (NO/ND) ---"
curl -s -X GET "$BASE/crypto/hsm/status" -H "$H" | pp
echo ""

# =============================================================================
# 2. HSM ECHO — B2/B3
# =============================================================================
echo "--- 2. HSM Echo (B2/B3) ---"
curl -s -X POST "$BASE/crypto/hsm/echo" -H "$H" -d '{"message":"HELLO"}' | pp
echo ""

# =============================================================================
# 3. KEY GENERATION — A0/A1
# =============================================================================
echo "--- 3a. Generate Symmetric Key ZMK (A0/A1) ---"
curl -s -X POST "$BASE/keys/symmetric" -H "$H" -d '{
  "label": "test-zmk-01",
  "keyType": "ZMK",
  "keyScheme": "U",
  "mode": "0"
}' | pp
echo ""

echo "--- 3b. Generate Symmetric Key ZPK (A0/A1) ---"
curl -s -X POST "$BASE/keys/symmetric" -H "$H" -d '{
  "label": "test-zpk-01",
  "keyType": "ZPK",
  "keyScheme": "U",
  "mode": "0"
}' | pp
echo ""

# =============================================================================
# 4. KEY IMPORT ZMK — A6/A7
# =============================================================================
echo "--- 4. Import Key under ZMK (A6/A7) ---"
curl -s -X POST "$BASE/keys/import-zmk-wrapped" -H "$H" -d "{
  \"label\": \"imported-zpk-zmk\",
  \"keyType\": \"ZPK\",
  \"zmkKeyId\": \"$KEY_ZMK\",
  \"keyUnderZmkHex\": \"A1B2C3D4E5F60718A1B2C3D4E5F60718A1B2C3D4E5F60718A1B2C3D4E5F60718\",
  \"keyScheme\": \"U\",
  \"zmkScheme\": \"U\"
}" | pp
echo ""

# =============================================================================
# 5. KEY COMPONENT GENERATE — A2/A3
# =============================================================================
echo "--- 5. Generate Key Component (A2/A3) ---"
curl -s -X POST "$BASE/crypto/key/component/generate" -H "$H" -d '{
  "keyType": "ZMK",
  "keyScheme": "U",
  "componentIndex": 1
}' | pp
echo ""

# =============================================================================
# 6. KEY FORM FROM COMPONENTS — A4/A5
# =============================================================================
echo "--- 6. Form Key from Components (A4/A5) ---"
curl -s -X POST "$BASE/crypto/key/form-from-components" -H "$H" -d '{
  "keyType": "ZMK",
  "keyScheme": "U",
  "components": [
    "UAABBCCDDEEAABBCCDDEEAABBCCDDEEAA",
    "U1122334455112233445511223344551122"
  ]
}' | pp
echo ""

# =============================================================================
# 7. KEY EXPORT under ZMK — A8/A9 (legacy)
# =============================================================================
echo "--- 7a. Export Key under ZMK (A8/A9) ---"
curl -s -X POST "$BASE/keys/$KEY_ZPK/export" -H "$H" -d "{
  \"format\": \"RAW\",
  \"schemeZmk\": \"U\",
  \"schemeLmk\": \"U\"
}" | pp
echo ""

echo "--- 7b. Export Key TR-31 (B4/B5) ---"
curl -s -X POST "$BASE/keys/$KEY_ZPK/export" -H "$H" -d "{
  \"format\": \"TR31_B\",
  \"kbpkKeyId\": \"$KEY_KBPK\"
}" | pp
echo ""

# =============================================================================
# 8. RSA KEY GEN — EI/EJ
# =============================================================================
echo "--- 8. Generate RSA Key Pair (EI/EJ) ---"
curl -s -X POST "$BASE/keys/rsa" -H "$H" -d '{
  "label": "test-rsa-2048",
  "modulusBits": 2048,
  "keyType": "2",
  "encoding": "0",
  "publicExponentHex": "010001"
}' | pp
echo ""

# =============================================================================
# 9. KEY IMPORT RSA-WRAPPED — GI/GJ
# =============================================================================
echo "--- 9. Import Key under RSA (GI/GJ) ---"
curl -s -X POST "$BASE/keys/import-rsa-wrapped" -H "$H" -d '{
  "label": "rsa-wrapped-key",
  "wrappingPublicKey": "3082010A...",
  "wrappedKey": "AABBCCDD...",
  "mode": "0",
  "hashId": "01",
  "keyType": "ZPK"
}' | pp
echo ""

# =============================================================================
# 10. KEY CHECK VALUE — BU/BV
# =============================================================================
echo "--- 10. Key Check Value (BU/BV) ---"
curl -s -X POST "$BASE/crypto/key/check-value" -H "$H" -d "{
  \"keyId\": \"$KEY_ZPK\"
}" | pp
echo ""

# =============================================================================
# 11. EXPORT ZPK under ZMK — GC/GD
# =============================================================================
echo "--- 11. Export ZPK under ZMK (GC/GD) ---"
curl -s -X POST "$BASE/crypto/key/export-zmk" -H "$H" -d "{
  \"zpkKeyId\": \"$KEY_ZPK\",
  \"zmkKeyId\": \"$KEY_ZMK\"
}" | pp
echo ""

# =============================================================================
# 12. DATA ENCRYPT — M0/M1
# =============================================================================
echo "--- 12. Encrypt Data (M0/M1) ---"
curl -s -X POST "$BASE/crypto/encrypt" -H "$H" -d "{
  \"keyId\": \"$KEY_3DES\",
  \"plaintextHex\": \"0102030405060708\",
  \"mode\": \"00\",
  \"iv\": \"0000000000000000\"
}" | pp
echo ""

# =============================================================================
# 13. DATA DECRYPT — M2/M3
# =============================================================================
echo "--- 13. Decrypt Data (M2/M3) ---"
curl -s -X POST "$BASE/crypto/decrypt" -H "$H" -d "{
  \"keyId\": \"$KEY_3DES\",
  \"ciphertextHex\": \"AABBCCDDEEFF0011\",
  \"mode\": \"00\",
  \"iv\": \"0000000000000000\"
}" | pp
echo ""

# =============================================================================
# 14. PIN GENERATE — JA/JB
# =============================================================================
echo "--- 14. Generate Random PIN under LMK (JA/JB) ---"
curl -s -X POST "$BASE/crypto/pin/generate" -H "$H" -d '{
  "pinLen": "4"
}' | pp
echo ""

# =============================================================================
# 15. PIN TRANSLATE TPK→ZPK — CA/CB
# =============================================================================
echo "--- 15. Translate PIN TPK→ZPK (CA/CB) ---"
curl -s -X POST "$BASE/crypto/pin/translate" -H "$H" -d "{
  \"tpkKeyId\": \"$KEY_TPK\",
  \"zpkKeyId\": \"$KEY_ZPK\",
  \"pinBlock\": \"0412AC3456FFFFFF\",
  \"pinBlockFormat\": \"01\",
  \"maxPinLen\": \"12\",
  \"pan\": \"123456789012345\"
}" | pp
echo ""

# =============================================================================
# 16. PIN TRANSLATE ZPK→ZPK — CC/CD
# =============================================================================
echo "--- 16. Translate PIN ZPK→ZPK (CC/CD) ---"
curl -s -X POST "$BASE/crypto/pin/translate-zpk" -H "$H" -d "{
  \"srcZpkKeyId\": \"$KEY_ZPK\",
  \"dstZpkKeyId\": \"$KEY_ZPK_DST\",
  \"pinBlock\": \"0412AC3456FFFFFF\",
  \"pinBlockFormat\": \"01\",
  \"dstFlag\": \"01\",
  \"srcFlag\": \"01\",
  \"pan\": \"123456789012345\"
}" | pp
echo ""

# =============================================================================
# 17. ENCRYPT CLEAR PIN — BA/BB
# =============================================================================
echo "--- 17. Encrypt Clear PIN under ZPK (BA/BB) ---"
curl -s -X POST "$BASE/crypto/pin/encrypt-clear" -H "$H" -d "{
  \"zpkKeyId\": \"$KEY_ZPK\",
  \"clearPin\": \"1234\",
  \"pinBlockFormat\": \"01\",
  \"pan\": \"123456789012345\"
}" | pp
echo ""

# =============================================================================
# 18. PIN TO LMK — JC (TPK) / JE (ZPK)
# =============================================================================
echo "--- 18a. PIN TPK→LMK (JC/JD) ---"
curl -s -X POST "$BASE/crypto/pin/to-lmk" -H "$H" -d "{
  \"inputKeyScheme\": \"TPK\",
  \"inputKeyId\": \"$KEY_TPK\",
  \"pinBlock\": \"0412AC3456FFFFFF\",
  \"pinBlockFormat\": \"01\",
  \"pan\": \"123456789012345\"
}" | pp
echo ""

echo "--- 18b. PIN ZPK→LMK (JE/JF) ---"
curl -s -X POST "$BASE/crypto/pin/to-lmk" -H "$H" -d "{
  \"inputKeyScheme\": \"ZPK\",
  \"inputKeyId\": \"$KEY_ZPK\",
  \"pinBlock\": \"0412AC3456FFFFFF\",
  \"pinBlockFormat\": \"01\",
  \"pan\": \"123456789012345\"
}" | pp
echo ""

# =============================================================================
# 19. PIN FROM LMK → ZPK — JG/JH
# =============================================================================
echo "--- 19. PIN LMK→ZPK (JG/JH) ---"
curl -s -X POST "$BASE/crypto/pin/from-lmk" -H "$H" -d "{
  \"zpkKeyId\": \"$KEY_ZPK\",
  \"pinUnderLmk\": \"D04462B4268DB9FC\",
  \"pan\": \"123456789012345\"
}" | pp
echo ""

# =============================================================================
# 20. PVV GENERATE — DG/DH
# =============================================================================
echo "--- 20. Generate VISA PVV (DG/DH) ---"
curl -s -X POST "$BASE/crypto/pin/pvv" -H "$H" -d "{
  \"pvkKeyId\": \"$KEY_PVK\",
  \"pinUnderLmk\": \"D04462B4268DB9FC\",
  \"pan\": \"4111111111111111\",
  \"pvki\": \"1\"
}" | pp
echo ""

# =============================================================================
# 21. IBM OFFSET GENERATE — DE/DF
# =============================================================================
echo "--- 21. Generate IBM PIN Offset (DE/DF) ---"
curl -s -X POST "$BASE/crypto/pin/ibm-offset" -H "$H" -d "{
  \"pvkKeyId\": \"$KEY_PVK\",
  \"pinUnderLmk\": \"D04462B4268DB9FC\",
  \"pan\": \"4111111111111111\",
  \"decimTable\": \"0123456789012345\",
  \"pinValidData\": \"111111111111\",
  \"checkLen\": \"4\"
}" | pp
echo ""

# =============================================================================
# 22. DERIVE IBM PIN — EE/EF
# =============================================================================
echo "--- 22. Derive IBM PIN from Offset (EE/EF) ---"
curl -s -X POST "$BASE/crypto/pin/derive-ibm" -H "$H" -d "{
  \"pvkKeyId\": \"$KEY_PVK\",
  \"offset\": \"01330000\",
  \"checkLen\": \"4\",
  \"accountNo\": \"111111111111\",
  \"decimTable\": \"0123456789012345\",
  \"pinValidData\": \"111111111111\"
}" | pp
echo ""

# =============================================================================
# 23. PIN VERIFY IBM — DA/DB
# =============================================================================
echo "--- 23. Verify Terminal PIN IBM (DA/DB) ---"
curl -s -X POST "$BASE/crypto/pin/verify" -H "$H" -d "{
  \"tpkKeyId\": \"$KEY_TPK\",
  \"pvkKeyId\": \"$KEY_PVK\",
  \"pinBlock\": \"0412AC3456FFFFFF\",
  \"pinBlockFormat\": \"01\",
  \"pan\": \"4111111111111111\",
  \"checkLen\": \"4\",
  \"decimTable\": \"0123456789012345\",
  \"pinOffset\": \"01330000\"
}" | pp
echo ""

# =============================================================================
# 24. PIN VERIFY VISA PVV — DC/DD
# =============================================================================
echo "--- 24. Verify Terminal PIN VISA PVV (DC/DD) ---"
curl -s -X POST "$BASE/crypto/pin/verify-visa" -H "$H" -d "{
  \"tpkKeyId\": \"$KEY_TPK\",
  \"pvkKeyId\": \"$KEY_PVK\",
  \"pinBlock\": \"0412AC3456FFFFFF\",
  \"pinBlockFormat\": \"01\",
  \"pan\": \"4111111111111111\",
  \"maxPinLen\": \"12\",
  \"pvki\": \"1\",
  \"pvv\": \"1234\"
}" | pp
echo ""

# =============================================================================
# 25. INTERCHANGE PIN VERIFY IBM — EA/EB
# =============================================================================
echo "--- 25. Verify Interchange PIN IBM (EA/EB) ---"
curl -s -X POST "$BASE/crypto/pin/verify-interchange-ibm" -H "$H" -d "{
  \"tpkKeyId\": \"$KEY_ZPK\",
  \"pvkKeyId\": \"$KEY_PVK\",
  \"pinBlock\": \"0412AC3456FFFFFF\",
  \"pinBlockFormat\": \"01\",
  \"pan\": \"4111111111111111\",
  \"checkLen\": \"4\",
  \"decimTable\": \"0123456789012345\",
  \"pinOffset\": \"01330000\"
}" | pp
echo ""

# =============================================================================
# 26. INTERCHANGE PIN VERIFY VISA — EC/ED
# =============================================================================
echo "--- 26. Verify Interchange PIN VISA (EC/ED) ---"
curl -s -X POST "$BASE/crypto/pin/verify-interchange-visa" -H "$H" -d "{
  \"tpkKeyId\": \"$KEY_ZPK\",
  \"pvkKeyId\": \"$KEY_PVK\",
  \"pinBlock\": \"0412AC3456FFFFFF\",
  \"pinBlockFormat\": \"01\",
  \"pan\": \"4111111111111111\",
  \"maxPinLen\": \"12\",
  \"pvki\": \"1\",
  \"pvv\": \"1234\"
}" | pp
echo ""

# =============================================================================
# 27. CVV GENERATE — CW/CX
# =============================================================================
echo "--- 27. Generate CVV/CVC (CW/CX) ---"
curl -s -X POST "$BASE/crypto/cvv/generate" -H "$H" -d "{
  \"cvkaKeyId\": \"$KEY_CVK_A\",
  \"cvkbKeyId\": \"$KEY_CVK_B\",
  \"pan\": \"4111111111111111\",
  \"expDate\": \"2512\",
  \"serviceCode\": \"101\"
}" | pp
echo ""

# =============================================================================
# 28. CVV VERIFY — CY/CZ
# =============================================================================
echo "--- 28. Verify CVV/CVC (CY/CZ) ---"
curl -s -X POST "$BASE/crypto/cvv/verify" -H "$H" -d "{
  \"cvkaKeyId\": \"$KEY_CVK_A\",
  \"cvkbKeyId\": \"$KEY_CVK_B\",
  \"pan\": \"4111111111111111\",
  \"expDate\": \"2512\",
  \"serviceCode\": \"101\",
  \"cvv\": \"123\"
}" | pp
echo ""

# =============================================================================
# 29. MAC GENERATE — M6/M7
# =============================================================================
echo "--- 29. Generate MAC (M6/M7) ---"
curl -s -X POST "$BASE/crypto/mac/generate" -H "$H" -d "{
  \"keyId\": \"$KEY_MAC\",
  \"dataHex\": \"0102030405060708090A0B0C0D0E0F10\",
  \"mode\": \"0\",
  \"algorithm\": \"03\",
  \"padding\": \"1\"
}" | pp
echo ""

# =============================================================================
# 30. MAC VERIFY — M8/M9
# =============================================================================
echo "--- 30. Verify MAC (M8/M9) ---"
curl -s -X POST "$BASE/crypto/mac/verify" -H "$H" -d "{
  \"keyId\": \"$KEY_MAC\",
  \"dataHex\": \"0102030405060708090A0B0C0D0E0F10\",
  \"mac\": \"FE592C8279B40932\",
  \"mode\": \"0\",
  \"algorithm\": \"03\",
  \"padding\": \"1\"
}" | pp
echo ""

# =============================================================================
# 31. ARQC VERIFY EMV 3.x — KQ/KR
# =============================================================================
echo "--- 31. Verify ARQC EMV 3.x (KQ/KR) ---"
curl -s -X POST "$BASE/crypto/arqc" -H "$H" -d "{
  \"imkKeyId\": \"$KEY_IMK\",
  \"mode\": \"0\",
  \"pan\": \"4111111111111111\",
  \"panSeqNo\": \"01\",
  \"atc\": \"0001\",
  \"arqc\": \"AABBCCDDEEFF0011\",
  \"transData\": \"0000000100000000000000000840960000000000000000000000\",
  \"arc\": \"3030\"
}" | pp
echo ""

# =============================================================================
# 32. ARQC VERIFY EMV 4.x — KW/KX
# =============================================================================
echo "--- 32. Verify ARQC EMV 4.x (KW/KX) ---"
curl -s -X POST "$BASE/crypto/arqc/emv4" -H "$H" -d "{
  \"imkKeyId\": \"$KEY_IMK\",
  \"mode\": \"0\",
  \"pan\": \"4111111111111111\",
  \"panSeqNo\": \"01\",
  \"atc\": \"0001\",
  \"arqc\": \"AABBCCDDEEFF0011\",
  \"transData\": \"0000000100000000000000000840960000000000000000000000\",
  \"arc\": \"3030\"
}" | pp
echo ""

# =============================================================================
# 33. dCVV VERIFY — PM/PN
# =============================================================================
echo "--- 33. Verify dCVV (PM/PN) ---"
curl -s -X POST "$BASE/crypto/dcvv/verify" -H "$H" -d "{
  \"keyId\": \"$KEY_IMK\",
  \"pan\": \"4111111111111111\",
  \"expiry\": \"2512\",
  \"serviceCode\": \"101\",
  \"atc\": \"0001\",
  \"dcvv\": \"123\"
}" | pp
echo ""

# =============================================================================
# 34. CSC CALCULATE — RY/RZ mode=3
# =============================================================================
echo "--- 34. Calculate CSC (RY/RZ mode=3) ---"
curl -s -X POST "$BASE/crypto/csc/calculate" -H "$H" -d "{
  \"keyId\": \"$KEY_IMK\",
  \"account\": \"4111111111111111\",
  \"expiry\": \"2512\",
  \"flag\": \"0\"
}" | pp
echo ""

# =============================================================================
# 35. CSC VERIFY — RY/RZ mode=4
# =============================================================================
echo "--- 35. Verify CSC (RY/RZ mode=4) ---"
curl -s -X POST "$BASE/crypto/csc/verify" -H "$H" -d "{
  \"keyId\": \"$KEY_IMK\",
  \"account\": \"4111111111111111\",
  \"expiry\": \"2512\",
  \"flag\": \"0\",
  \"csc3\": \"123\"
}" | pp
echo ""

# =============================================================================
# 36. HMAC GENERATE — LQ/LR
# =============================================================================
echo "--- 36. Generate HMAC (LQ/LR) ---"
curl -s -X POST "$BASE/crypto/hmac/generate" -H "$H" -d "{
  \"keyId\": \"$KEY_HMAC\",
  \"dataHex\": \"0102030405060708090A0B0C0D0E0F10\",
  \"algorithm\": \"SHA-256\"
}" | pp
echo ""

# =============================================================================
# 37. HMAC VERIFY — LS/LT
# =============================================================================
echo "--- 37. Verify HMAC (LS/LT) ---"
curl -s -X POST "$BASE/crypto/hmac/verify" -H "$H" -d "{
  \"keyId\": \"$KEY_HMAC\",
  \"dataHex\": \"0102030405060708090A0B0C0D0E0F10\",
  \"hmac\": \"AABBCCDDEEFF0011AABBCCDDEEFF0011\",
  \"algorithm\": \"SHA-256\"
}" | pp
echo ""

# =============================================================================
# 38. GENERATE KEY (HC/HD) — Generate TMK/TPK/PVK under LMK
# =============================================================================
echo "--- 38. Generate TMK/TPK Key (HC/HD) ---"
curl -s -X POST "$BASE/crypto/key/generate-tpk" -H "$H" -d '{
  "label": "test-tpk-01",
  "keyScheme": "U"
}' | pp
echo ""

# =============================================================================
# 39. GENERATE ZPK (IA/IB)
# =============================================================================
echo "--- 39. Generate ZPK (IA/IB) ---"
curl -s -X POST "$BASE/crypto/key/generate-zpk" -H "$H" -d '{
  "label": "test-zpk-ia",
  "keyScheme": "U"
}' | pp
echo ""

# =============================================================================
# 40. DECRYPT ENCRYPTED PIN (NG/NH)
# =============================================================================
echo "--- 40. Decrypt Encrypted PIN (NG/NH) ---"
curl -s -X POST "$BASE/crypto/pin/decrypt" -H "$H" -d "{
  \"keyId\": \"$KEY_TPK\",
  \"pinBlock\": \"0412AC3456FFFFFF\",
  \"pinBlockFormat\": \"01\",
  \"pan\": \"123456789012345\"
}" | pp
echo ""

# =============================================================================
# 41. GENERATE RANDOM DATA (OA/OB)
# =============================================================================
echo "--- 41. Generate Random Data (OA/OB) ---"
curl -s -X POST "$BASE/crypto/random" -H "$H" -d '{
  "numBytes": 16
}' | pp
echo ""

# =============================================================================
# 42. TRANSLATE PIN ZPK→ZPK variant (JS/JT)
# =============================================================================
echo "--- 42. Translate PIN ZPK→ZPK variant (JS/JT) ---"
curl -s -X POST "$BASE/crypto/pin/translate-zpk2" -H "$H" -d "{
  \"srcZpkKeyId\": \"$KEY_ZPK\",
  \"dstZpkKeyId\": \"$KEY_ZPK_DST\",
  \"pinBlock\": \"0412AC3456FFFFFF\",
  \"pinBlockFormat\": \"01\",
  \"dstFlag\": \"01\",
  \"srcFlag\": \"01\",
  \"pan\": \"123456789012345\"
}" | pp
echo ""

# =============================================================================
# 43. VERIFY MAC ALTERNATE (VA/VB)
# =============================================================================
echo "--- 43. Verify MAC Alternate (VA/VB) ---"
curl -s -X POST "$BASE/crypto/mac/verify-alt" -H "$H" -d "{
  \"keyId\": \"$KEY_MAC\",
  \"dataHex\": \"0102030405060708090A0B0C0D0E0F10\",
  \"mac\": \"FE592C8279B40932\",
  \"mode\": \"0\",
  \"algorithm\": \"03\",
  \"padding\": \"1\"
}" | pp
echo ""

echo "=== All tests complete ==="
