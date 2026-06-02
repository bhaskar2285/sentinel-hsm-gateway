# Sentinel HSM Gateway — Laptop Setup Guide

Complete procedure to run Sentinel HSM Gateway + Thales Go Simulator on a development laptop.

---

## Prerequisites

| Tool | Version | Install |
|------|---------|---------|
| Docker Desktop | 4.x+ | https://docs.docker.com/desktop/ |
| Docker Compose | v2 (bundled with Desktop) | — |
| JDK | 25 | `sdk install java 25-tem` |
| Maven | 3.9+ | `sdk install maven` |
| Go | 1.22+ | https://go.dev/dl/ |
| Git | any | package manager |

> **ARM64 laptop (Apple Silicon / Raspberry Pi):** builds work natively. Go cross-compile step below.

---

## Repository Layout

```
~/
  sentinel-hsm-gateway/     ← Spring Boot gateway + Postgres
  thales-go-sim/            ← Go HSM simulator (5 instances)
  sentinel-vault-ui/        ← React frontend
```

---

## Step 1 — Build the Thales Go Simulator

```bash
cd ~/thales-go-sim

# Build Linux binary (ARM64 host)
GOOS=linux GOARCH=arm64 go build -o thales-go-sim .

# Build Linux binary (x86_64 host)
# GOOS=linux GOARCH=amd64 go build -o thales-go-sim .

# Build Docker image
docker build -t thales-go-sim:latest .

# Start 5 simulator instances (ports 9998–10002)
docker compose up -d
```

Verify:
```bash
docker ps | grep thales-sim
# Should show 5 running containers
```

---

## Step 2 — Build the Gateway JAR

```bash
cd ~/sentinel-hsm-gateway

mvn package -q -DskipTests
# JAR lands at: modules/gateway-api/target/sentinel-hsm-gateway.jar
```

---

## Step 3 — Start Gateway + Postgres

```bash
cd ~/sentinel-hsm-gateway

docker compose build
docker compose up -d --force-recreate
```

Wait ~10 seconds for startup:
```bash
curl http://localhost:8090/actuator/health
# {"status":"UP"}
```

### Default credentials
| Service | URL | User | Password |
|---------|-----|------|----------|
| Gateway API | http://localhost:8090 | — | — |
| Gateway console | http://localhost:8090/sentinel | admin | sentinel123 |
| Postgres | localhost:5434 | sentinel | sentinel |

---

## Step 4 — Register HSM Nodes

The gateway load-balances across HSM node entries in the DB. After first startup, insert the 5 simulator nodes:

```bash
TOKEN=$(curl -s -X POST http://localhost:8090/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"sentinel123"}' | jq -r '.token')

for PORT in 9998 9999 10000 10001 10002; do
  curl -s -X POST http://localhost:8090/api/v1/admin/hsm-nodes \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"vendor\":\"THALES\",\"host\":\"host.docker.internal\",\"port\":$PORT,\"weight\":1}"
done
```

---

## Step 5 — Create a Bank (Institution)

```bash
curl -s -X POST http://localhost:8090/api/v1/admin/banks \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"Demo Bank","code":"DEMO"}'
# Note the returned bankId / recId
```

---

## Step 6 — Run the API Test Script

```bash
cd ~/sentinel-hsm-gateway

# Edit SENTINEL_API_TESTS.sh — set variables at top:
#   BASE_URL, TOKEN, BANK_ID, KEY_ZMK, KEY_ZPK, etc.

chmod +x SENTINEL_API_TESTS.sh
./SENTINEL_API_TESTS.sh
```

The script tests all 43 command endpoints.

---

## Step 7 — Start the Frontend (optional)

```bash
cd ~/sentinel-vault-ui
npm install
npm run dev
# Opens at http://localhost:5173
```

---

## Rebuild Cycle (after code changes)

### Gateway only:
```bash
cd ~/sentinel-hsm-gateway
mvn package -q -DskipTests && \
docker compose build && \
docker compose up -d --force-recreate
```

### Go sim only:
```bash
cd ~/thales-go-sim
GOOS=linux GOARCH=arm64 go build -o thales-go-sim . && \
docker build -t thales-go-sim:latest . && \
docker compose up -d --force-recreate
```

### Full rebuild (both):
```bash
cd ~/thales-go-sim
GOOS=linux GOARCH=arm64 go build -o thales-go-sim .
docker build -t thales-go-sim:latest .
docker compose up -d --force-recreate

cd ~/sentinel-hsm-gateway
mvn package -q -DskipTests
docker compose build
docker compose up -d --force-recreate
```

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DB_URL` | `jdbc:postgresql://postgres:5432/sentinel` | Postgres JDBC URL |
| `DB_USER` | `sentinel` | DB user |
| `DB_PASS` | `sentinel` | DB password |
| `SPRING_PROFILES_ACTIVE` | `dev` | `dev` = no OAuth, `prod` = JWT required |
| `OAUTH_ISSUER` | (empty) | OIDC issuer URL for prod profile |

---

## API Endpoints Summary

All endpoints require `Authorization: Bearer <jwt>` header.
In `dev` profile any valid (or empty) bearer is accepted.

### Key Management
| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/key/generate` | Generate symmetric key (A0) |
| POST | `/api/v1/key/import-zmk` | Import key under ZMK (A6) |
| POST | `/api/v1/key/export` | Export key under ZMK (A8) |
| POST | `/api/v1/key/form-block` | Wrap key in TR-31 block (B4) |
| POST | `/api/v1/key/rsa/generate` | Generate RSA key pair (EI) |
| POST | `/api/v1/key/rsa/import` | Import RSA-wrapped key (GI) |
| POST | `/api/v1/key/component/generate` | Generate key component (A2) |
| POST | `/api/v1/key/form-from-components` | Form key from XOR'd components (A4) |
| POST | `/api/v1/key/check-value` | Generate key check value (BU) |
| POST | `/api/v1/key/export-zmk` | Export ZPK under ZMK (GC) |
| POST | `/api/v1/crypto/key/generate-tpk` | Generate TPK under LMK (HC) |
| POST | `/api/v1/crypto/key/generate-zpk` | Generate ZPK under LMK (IA) |

### Crypto / Encryption
| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/crypto/encrypt` | Encrypt data block (M0) |
| POST | `/api/v1/crypto/decrypt` | Decrypt data block (M2) |
| POST | `/api/v1/crypto/random` | Generate random data (OA) |

### PIN Operations
| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/crypto/pin/generate` | Generate random PIN (JA) |
| POST | `/api/v1/crypto/pin/translate` | Translate PIN TPK→ZPK (CA) |
| POST | `/api/v1/crypto/pin/translate-zpk` | Translate PIN ZPK→ZPK (CC) |
| POST | `/api/v1/crypto/pin/translate-zpk2` | Translate PIN ZPK→ZPK v2 (JS) |
| POST | `/api/v1/crypto/pin/encrypt-clear` | Encrypt clear PIN under ZPK (BA) |
| POST | `/api/v1/crypto/pin/to-lmk` | Translate PIN TPK/ZPK → LMK (JC/JE) |
| POST | `/api/v1/crypto/pin/from-lmk` | Translate PIN LMK → ZPK (JG) |
| POST | `/api/v1/crypto/pin/verify` | Verify PIN IBM 3624 (DA) |
| POST | `/api/v1/crypto/pin/verify-visa` | Verify PIN VISA PVV (DC) |
| POST | `/api/v1/crypto/pin/verify-interchange-ibm` | Verify interchange PIN IBM (EA) |
| POST | `/api/v1/crypto/pin/verify-interchange-visa` | Verify interchange PIN VISA (EC) |
| POST | `/api/v1/crypto/pin/ibm-offset` | Generate IBM PIN offset (DE) |
| POST | `/api/v1/crypto/pin/derive-ibm` | Derive PIN from IBM offset (EE) |
| POST | `/api/v1/crypto/pin/decrypt` | Decrypt encrypted PIN block (NG) |
| POST | `/api/v1/crypto/pin/pvv` | Generate VISA PVV (DG) |

### MAC Operations
| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/crypto/mac/generate` | Generate MAC (M6) |
| POST | `/api/v1/crypto/mac/verify` | Verify MAC (M8) |
| POST | `/api/v1/crypto/mac/verify-alt` | Verify MAC full-format variant (VA) |

### CVV / CSC
| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/crypto/cvv/generate` | Generate CVV/CVC (CW) |
| POST | `/api/v1/crypto/cvv/verify` | Verify CVV/CVC (CY) |
| POST | `/api/v1/crypto/dcvv/verify` | Verify dynamic CVV (PM) |
| POST | `/api/v1/crypto/csc/calculate` | Calculate CSC (RY mode 3) |
| POST | `/api/v1/crypto/csc/verify` | Verify CSC (RY mode 4) |

### ARQC / EMV
| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/crypto/arqc` | Verify ARQC / Generate ARPC (KQ) |
| POST | `/api/v1/crypto/arqc/emv4` | Verify ARQC EMV 4.x (KW) |

### HMAC
| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/crypto/hmac/generate` | Generate HMAC (LQ) |
| POST | `/api/v1/crypto/hmac/verify` | Verify HMAC (LS) |

### HSM / Diagnostics
| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/crypto/hsm/status` | HSM status (NO) |
| POST | `/api/v1/crypto/hsm/echo` | HSM echo / loopback (B2) |

---

## Database

Flyway manages schema migrations automatically on startup.

```bash
# Connect to Postgres (from host)
psql -h localhost -p 5434 -U sentinel -d sentinel

# Useful queries
\dt                          -- list all tables
SELECT * FROM hsm_key;       -- list stored keys
SELECT * FROM hsm_node;      -- list HSM nodes
SELECT * FROM bank;          -- list institutions
```

---

## Logs

```bash
# Gateway logs (follow)
docker logs -f sentinel-hsm-gateway

# Go sim logs (follow, instance 1)
docker logs -f thales-sim-1
```

---

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| `{"status":"DOWN"}` | Check DB is up: `docker ps` → postgres healthy |
| `Connection refused :8090` | Gateway still starting — wait 10s |
| HSM error 10 | Decryption failed — key type or LMK mismatch |
| HSM error 15 | Malformed request — check field lengths/formats |
| `key not found` | Key UUID wrong or wrong bank scope (check X-Bank-Id header) |
| Flyway checksum error | Migrations are immutable — never edit applied SQL files |
| Port 8090 in use | Change host port in docker-compose.yml: `"8091:8080"` |

---

## Key Type → LMK Pair Codes

| Key Type | Thales LMK Pair | Notes |
|----------|----------------|-------|
| ZMK | 000 | Zone Master Key |
| ZPK, BDK | 001 | Zone PIN Key / Base Derivation Key |
| KBPK | 002 | Key Block Protection Key |
| TMK, TPK | 008 | Terminal Master/PIN Key |
| DATA, PVK, CVK | 00A | Data encryption, PIN verification, card verification |

---

## Pushing to Production

1. Set `SPRING_PROFILES_ACTIVE=prod` and `OAUTH_ISSUER=<your-issuer>` in docker-compose.yml or env
2. Point `DB_URL`, `DB_USER`, `DB_PASS` at production Postgres
3. Add real HSM node entries pointing at physical Thales payShield 10K host:port
4. Replace `thales-go-sim` containers with physical HSMs (remove the sim compose)
5. Enable TLS: set `sentinel.thales.tls.enabled=true` in application.properties

---

*Generated for Sentinel HSM Gateway — internal use.*
