# Sentinel HSM Gateway — Project Bible

> Complete reference: architecture, code flows, every layer, every endpoint, database schema, wire protocol.

---

## 1. What It Is

`sentinel-hsm-gateway` is a Java 25 / Spring Boot 3.5 multi-module application that acts as a secure, multi-tenant REST gateway to Thales payShield 10K (and Utimaco) HSMs. It translates REST/JSON calls into native HSM wire commands, manages connection pools to multiple HSMs, persists key metadata, provides a full SAM-based RBAC auth system, and records an immutable audit log of every operation.

**It does NOT replace** `thales-artemis-lb` — it coexists, targeting different use cases (REST API clients vs native Artemis/ISO8583 flows).

---

## 2. Technology Stack

| Layer | Technology |
|-------|-----------|
| Language | Java 25 |
| Framework | Spring Boot 3.5 |
| Build | Maven 3 multi-module (`-T 1C` parallel) |
| Database | PostgreSQL 16 (host port 5434) |
| Schema | Flyway 4 migrations |
| ORM | JPA / Hibernate 6 |
| Connection pool | HikariCP (max 20) |
| HSM TCP pool | Apache Commons Pool2 |
| Auth | Custom SHA-256 token + session table (not OAuth2 in practice) |
| API docs | SpringDoc OpenAPI 3 / Swagger UI |
| Container | Docker Compose (network_mode: host) |
| Monitoring | Actuator + Prometheus + Grafana |

---

## 3. Module Structure

```
sentinel-hsm-gateway/
├── modules/
│   ├── gateway-api/           ← Spring Boot app entry point
│   ├── gateway-core/          ← Dispatcher, load balancer, health probe
│   ├── gateway-security/      ← SecurityConfig, JWT/RBAC
│   ├── gateway-persistence/   ← JPA entities, repos, Flyway migrations
│   ├── gateway-keyblock/      ← TR-31 / X9.143 key block codecs
│   ├── gateway-vendor-spi/    ← Vendor-neutral interfaces (OpCode, GatewayCommand)
│   ├── gateway-vendor-thales/ ← Thales payShield 10K implementation
│   └── gateway-vendor-utimaco/← Utimaco stub (future)
├── docker-compose.yml
└── pom.xml
```

**Dependency order:** `gateway-vendor-spi` ← `gateway-persistence` ← `gateway-core` ← `gateway-vendor-thales` ← `gateway-api`

---

## 4. Configuration (application.yml)

```yaml
server.port: 8090            # host port (network_mode: host)

spring.datasource.url: jdbc:postgresql://localhost:5434/sentinel
spring.datasource.username: sentinel

sentinel.thales:
  header: "0000"             # 4-byte ASCII HSM header
  connect-timeout-ms: 60000
  read-timeout-ms: 60000
  pool-max-per-node: 8       # max TCP sockets per HSM node

sentinel.security.dev-mode: false   # true = permit all + inject all OP_ authorities
```

---

## 5. Authentication & Security

### Login Flow

```
POST /api/v1/auth/login  {loginname, password}
        │
        ▼
AuthController → AuthService.login()
        │
        ├─ staffRepo.findByStaffLoginname()    (isc_sam_staff)
        ├─ check userStatusCode == "ACTIVE"
        ├─ check badLoginpwdCount < 5
        ├─ bankRepo.findById(staff.msBankId)   (isc_ms_bank)
        │
        ├─ login_method_type = "DB"   → SHA-256(loginname:password) vs stored hash
        ├─ login_method_type = "LDAP" → JNDI bind to ldap_ip:ldap_port
        └─ login_method_type = "MSAD" → JNDI bind with userPrincipalName
        │
        ▼
IscSamSession row inserted (32-byte random hex token, TTL 12h)
        │
        ▼
Response: { token, staffId, bankId, bankCode }
```

**Password hash:** `SHA-256(loginname + ":" + password)` stored hex in `isc_sam_staff.staff_loginpwd`.

**Failed login:** increments `bad_loginpwd_count`; at 5 → status=LOCKED.

### Token Validation

Every subsequent request: `Authorization: Bearer <64-hex-token>` → looked up in `isc_sam_session`. Spring Security configured as stateless. In **dev-mode** all requests permitted + all `OP_*` authorities injected automatically.

### SecurityConfig — Permitted Without Auth
- `GET /actuator/health`, `/actuator/info`
- `GET /v3/api-docs/**`, `/swagger-ui/**`
- `GET /api/v1/jwe/public-key`

### RBAC Operations (OP_ prefix)

| Authority | Controls |
|-----------|---------|
| `OP_KEY_CREATE_RSA` | POST /api/v1/keys/rsa |
| `OP_KEY_CREATE_SYM` | POST /api/v1/keys/symmetric |
| `OP_KEY_IMPORT` | POST /api/v1/keys/import-* |
| `OP_KEY_EXPORT` | POST /api/v1/keys/{id}/export |
| `OP_KEY_READ` | GET /api/v1/keys/** |
| `OP_CRYPTO_ENCRYPT` | POST /api/v1/crypto/encrypt |
| `OP_CRYPTO_DECRYPT` | POST /api/v1/crypto/decrypt |
| `OP_RAW_CMD` | POST /thales/command/{cmd} |
| `OP_ADMIN_AUDIT` | GET /api/v1/audit |
| `OP_ADMIN_RBAC` | /api/v1/admin/sam/** |

---

## 6. End-to-End Code Flow

### Path 1: Raw Thales Command (POST /thales/command/A0)

```
HTTP Client
    │  POST /thales/command/A0
    │  Authorization: Bearer <token>
    │  Body: {"keyType":"001","keyScheme":"U"}
    ▼
[SecurityConfig] — token → IscSamSession lookup → Spring SecurityContext
    ▼
[ThalesCommandController]
    │  servicesByCode.get("A0") → A0CommandService
    ▼
[A0CommandService.execute(params)]
    │  GatewayCommand{op=KEY_GEN, vendorHint=THALES, params}
    ▼
[CommandDispatcher.dispatch(cmd)]
    │  vendor = THALES → ThalesVendorAdapter
    │  PoolRouter.route(THALES, null)
    │    └─ poolRepo.findByVendorAndEnabledTrue("THALES") → HsmPool
    │    └─ nodeRepo.findByPoolIdAndEnabledTrue(poolId)
    │    └─ filter: health=UP or UNKNOWN
    │    └─ lb_strategy=ROUND_ROBIN → HsmNodeRef{host, port}
    │  adapter.execute(cmd, node)
    ▼
[ThalesVendorAdapter.execute(cmd, node)]
    │  buildRequest: KEY_GEN → ThalesCmdBuilder.buildA0(header, params)
    │    └─ body = "0" + "001" + "U"  (mode+keyType+keyScheme)
    │    └─ HsmWireMessage{header="0000", cmd="A0", body}
    │  wireBytes = [2-byte BE len][4-byte "0000"][2-byte "A0"][body]
    ▼
[ThalesTransport.roundTrip(node, wireBytes)]
    │  borrow Socket from Apache Commons Pool2 (per nodeId)
    │  write wireBytes → TCP → HSM
    │  read response: readUnsignedShort() = length, readFully(body)
    │  return body on success; invalidate socket on error
    ▼
[ThalesCmdParser.parse(respBody, headerLen, "A1")]
    │  strip 2-byte length + 4-byte header
    │  check response code = "A1"
    │  extract errCode(2) + scheme(1) + keyUnderLmk(hex) + kcv(6)
    │  return Parsed{errorCode, fields}
    ▼
[ThalesVendorAdapter] → GatewayResponse{status=OK, errCode=00, result={keyUnderLmk, scheme, kcv}}
    ▼
[CommandDispatcher] → AuditService.record(cmd, resp, node, traceId)
    ▼
[A0CommandService] → Map<String,Object>{keyUnderLmk, scheme, kcv, errCode, status}
    ▼
[ThalesCommandController] → ResponseEntity.ok(result)
    ▼
HTTP Client ← {"keyUnderLmk":"...","scheme":"U","kcv":"...","errCode":"00","status":"OK"}
```

### Path 2: Semantic API (POST /api/v1/keys/symmetric)

```
POST /api/v1/keys/symmetric  {label, keyType, keyScheme, ...}
    ▼
KeyController → KeyService.generateSymmetric()
    │  familyCodeForKeyType("ZMK") → "000"
    │  GatewayCommand{op=KEY_GEN, params={keyType:"000", keyScheme:"U"}}
    ▼
CommandDispatcher → ThalesVendorAdapter → HSM  (same as above)
    ▼
KeyService: HSM returns keyUnderLmk
    │  save HsmKey{keyUuid, label, keyType, algo, kcv, encryptedBlob, bankRecId, ...}
    ▼
Response: SymKeyGenResponse{keyId, kcv, scheme, ...}
```

---

## 7. All REST Endpoints

### Auth
| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/auth/login` | Login → token |
| POST | `/api/v1/auth/logout` | Invalidate session |
| POST | `/api/v1/auth/hash-password` | Utility: compute DB password hash |

### Keys
| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/keys/rsa` | Generate RSA key pair |
| POST | `/api/v1/keys/symmetric` | Generate symmetric key (A0) |
| POST | `/api/v1/keys/import-rsa-wrapped` | Import key under RSA public key (GI) |
| POST | `/api/v1/keys/import-zmk-wrapped` | Import key under ZMK (A6) |
| POST | `/api/v1/keys/{id}/export` | Export key TR-31/X9.143/raw (A8/B4) |
| GET | `/api/v1/keys` | List keys (filter by label, keyType) |
| GET | `/api/v1/keys/{id}` | Get key detail |

### Crypto (semantic)
| Method | Path | Thales cmd | Description |
|--------|------|-----------|-------------|
| POST | `/api/v1/crypto/encrypt` | M0 | Encrypt data block |
| POST | `/api/v1/crypto/decrypt` | M2 | Decrypt data block |
| POST | `/api/v1/crypto/pin/translate` | CA | PIN TPK→ZPK |
| POST | `/api/v1/crypto/pin/verify` | DA | Verify PIN IBM 3624 |
| POST | `/api/v1/crypto/pin/verify-visa` | DC | Verify PIN VISA PVV |
| POST | `/api/v1/crypto/pin/verify-interchange-ibm` | EA | Interchange IBM |
| POST | `/api/v1/crypto/pin/verify-interchange-visa` | EC | Interchange VISA |
| POST | `/api/v1/crypto/pin/generate` | JA | Generate random PIN |
| POST | `/api/v1/crypto/pin/encrypt-clear` | BA | Encrypt clear PIN |
| POST | `/api/v1/crypto/pin/decrypt` | NG | Decrypt PIN block |
| POST | `/api/v1/crypto/pin/to-lmk` | JC/JE | PIN TPK/ZPK → LMK |
| POST | `/api/v1/crypto/pin/from-lmk` | JG | PIN LMK → ZPK |
| POST | `/api/v1/crypto/pin/translate-zpk` | CC | PIN ZPK→ZPK |
| POST | `/api/v1/crypto/pin/ibm-offset` | DE | IBM PIN offset |
| POST | `/api/v1/crypto/pin/pvv` | DG | VISA PVV |
| POST | `/api/v1/crypto/pin/derive-ibm` | EE | Derive PIN from offset |
| POST | `/api/v1/crypto/cvv/generate` | CW | Generate CVV/CVC/CVV2 |
| POST | `/api/v1/crypto/cvv/verify` | CY | Verify CVV/CVC/CVV2 |
| POST | `/api/v1/crypto/arqc` | KQ | Verify ARQC / generate ARPC |
| POST | `/api/v1/crypto/arqc/emv4` | KW | ARQC EMV 4.x |
| POST | `/api/v1/crypto/dcvv/verify` | PM | Verify dCVV CVN17 |
| POST | `/api/v1/crypto/csc/calculate` | RY | Calculate CSC/AEVV |
| POST | `/api/v1/crypto/mac/generate` | M6 | Generate MAC |
| POST | `/api/v1/crypto/mac/verify` | M8 | Verify MAC |
| POST | `/api/v1/crypto/mac/verify-alt` | VA | Verify MAC (full-format) |
| POST | `/api/v1/crypto/hmac/generate` | LQ | Generate HMAC SPA2 |
| POST | `/api/v1/crypto/hmac/verify` | LS | Verify HMAC |
| POST | `/api/v1/crypto/key/export-zmk` | GC | Export ZPK under ZMK |
| POST | `/api/v1/crypto/key/check-value` | BU | Key check value |
| POST | `/api/v1/crypto/key/component/generate` | A2 | Key component |
| POST | `/api/v1/crypto/key/form-from-components` | A4 | Form key from components |
| GET | `/api/v1/crypto/hsm/status` | NO | HSM status |
| POST | `/api/v1/crypto/hsm/echo` | B2 | Echo loopback |

### Raw Thales Commands
```
POST /thales/command/{CMD}
Body: raw params map (HSM-native codes)
Auth: OP_RAW_CMD required
```
All 44 commands supported (see README for full list).

### Admin / Fleet
| Method | Path | Description |
|--------|------|-------------|
| GET/POST | `/api/v1/admin/banks` | Bank CRUD |
| GET | `/api/v1/admin/banks/{id}/branches` | Branch list |
| GET/POST | `/api/v1/pools` | HSM pool management |
| GET/POST/PUT/DELETE | `/api/v1/hsms` | HSM node CRUD |
| POST | `/api/v1/hsms/{id}/enable` | Enable node |
| POST | `/api/v1/hsms/{id}/disable` | Disable node |
| POST | `/api/v1/hsms/{id}/drain` | Drain node |
| GET | `/api/v1/audit` | Audit log (filter: bank, date, cmd) |

### SAM RBAC
| Method | Path | Description |
|--------|------|-------------|
| GET/POST | `/api/v1/admin/sam/banks/{bankId}/staff` | Staff management |
| POST | `/api/v1/admin/sam/staff/{id}/reset-password` | Reset password |
| GET/POST | `/api/v1/admin/sam/banks/{bankId}/roles` | Role management |
| GET/POST | `/api/v1/admin/sam/banks/{bankId}/teams` | Team management |
| POST | `/api/v1/admin/sam/teams/{teamId}/roles/{roleId}` | Bind role to team |
| GET/POST | `/api/v1/admin/sam/roles/{roleId}/permissions` | Permissions |

---

## 8. Database Schema

### Core Tables

**`hsm_pool`** — groups HSM nodes by vendor
- `id`, `vendor` (THALES/UTIMACO), `name`, `lb_strategy` (ROUND_ROBIN/WEIGHTED/LEAST_CONN/STICKY_KEY), `enabled`

**`hsm_node`** — individual HSM endpoints
- `id`, `pool_id`, `vendor`, `host`, `port`, `weight`, `direction` (OUTBOUND/INBOUND), `health` (UP/DOWN/UNKNOWN/DRAINING), `last_seen`

**`hsm_key`** — key metadata vault
- `key_uuid` (UUID), `label`, `key_type` (ZMK/ZPK/TPK/RSA/AES/...), `algo`, `key_length_bits`, `usage`, `kcv`, `encrypted_blob` (BYTEA — key under LMK), `status` (ACTIVE/REVOKED/EXPIRED), `bank_rec_id`, `branch_rec_id`, `expires_at`, `tags` (JSONB)

**`hsm_key_block`** — TR-31/X9.143 wrapped payloads
- `key_id`, `format` (TR31_B/TR31_D/X9_143/RAW), `payload`, `kbpk_id`

**`hsm_command_audit`** — immutable operation log
- `ts`, `user_id`, `op`, `vendor_cmd_code`, `key_id`, `hsm_node_id`, `latency_ms`, `status`, `err_code`, `err_text`, `trace_id`

### SAM Tables

**`isc_ms_bank`** — bank tenants (login_method_type: DB/LDAP/MSAD)  
**`isc_ms_branch`** — branches per bank  
**`isc_sam_staff`** — users (staff_loginname, staff_loginpwd SHA-256, user_status_code, bad_loginpwd_count)  
**`isc_sam_session`** — active sessions (session_token, expires_at, ip_address)  
**`isc_sam_team`** — teams per bank  
**`isc_sam_role`** — roles per bank  
**`isc_sam_team_role`** — team↔role mapping  
**`isc_sam_action`** — available operations  
**`isc_sam_access_control`** — role↔menu↔action grants  

### Flyway Migrations
- `V1__init.sql` — core schema: hsm_pool, hsm_node, hsm_key, audit, rbac seed
- `V2__isc_template_and_fi.sql` — bank/branch/FI templates
- `V3__isc_sam_rbac.sql` — SAM staff/team/role/session tables
- `V4__mark_dangling_keys_invalid.sql` — cleanup orphaned keys

---

## 9. Load Balancer & Health Probe

### PoolRouter

Routes each `CommandDispatcher.dispatch()` call to a healthy HSM node:
1. `poolRepo.findByVendorAndEnabledTrue(vendor)` → first matching pool
2. `nodeRepo.findByPoolIdAndEnabledTrue(poolId)` → filter health=UP or UNKNOWN
3. Apply `lb_strategy`:
   - `ROUND_ROBIN` — atomic counter per pool (mod node count)
   - `WEIGHTED` — random weighted selection by node.weight
   - `STICKY_KEY` — hash(keyId) mod node count
   - `LEAST_CONN` — TODO (currently same as index 0)

### HealthProbeService

Scheduled every 15s (initial delay 5s):
- Iterates all enabled nodes
- Calls `adapter.health(node)` — TCP connect+close (no HSM command)
- Updates `hsm_node.health` = UP/DOWN and `last_seen`
- Logs transition changes

---

## 10. Thales Wire Protocol

```
Request frame:
  [2-byte BE length][4-byte ASCII header "0000"][2-byte command][body]

Response frame:
  [2-byte BE length][4-byte ASCII header "0000"][2-byte resp-cmd][2-byte err-code][body]
```

**Header:** `"0000"` — 4 ASCII bytes. Configured in `application.yml` as `sentinel.thales.header`.

**Length field:** covers everything AFTER the 2-byte length itself.

**Error code `00`** = success. All codes in `ThalesErrorCode.java`.

### Key Schemes

| Code | Type | Bytes | Hex chars |
|------|------|-------|-----------|
| `U` | Double-length DES | 16 | 32 |
| `T` | Triple-length DES | 24 | 48 |
| `X` | AES-128 | 16 | 32 |

### A0 keyType Codes (differs from BU)

| Code | A0 meaning | BU meaning |
|------|-----------|-----------|
| `000` | ZMK | — |
| `001` | ZPK | ZMK |
| `002` | TPK | — |
| `00A` | DATA | — |
| `011` | — | ZPK |
| `008` | — | TPK |

---

## 11. Key Classes Reference

### gateway-vendor-spi

| Class | Role |
|-------|------|
| `OpCode` | Vendor-neutral operation enum (KEY_GEN, PIN_VERIFY, CVV_GEN, NET_HEALTH, ...) |
| `GatewayCommand` | Request DTO: op, vendorHint, params Map, userId, keyId, traceId |
| `GatewayResponse` | Response DTO: status, errCode, errText, result Map, latencyMs |
| `HsmNodeRef` | Node pointer: id, vendor, host, port, weight, direction |
| `HsmVendorAdapter` | Interface: vendor(), supports(OpCode), execute(cmd, node), health(node) |
| `HsmVendor` | Enum: THALES, UTIMACO |

### gateway-vendor-thales

| Class | Role |
|-------|------|
| `ThalesVendorAdapter` | Implements HsmVendorAdapter; routes OpCode → builder; calls transport; parses response |
| `ThalesCmdBuilder` | Static methods: buildA0/A6/A8/BU/GC/NC/... → HsmWireMessage |
| `ThalesCmdParser` | Static parse(): raw bytes → Parsed{errorCode, fields Map} |
| `ThalesCommandCode` | Enum of all 44 Thales command/response code pairs + spec page refs |
| `ThalesErrorCode` | Static describe(code) → human error text |
| `ThalesTransport` | Per-node Apache Commons Pool2 TCP socket pool; roundTrip() |
| `ThalesSocketFactory` | Pool2 factory: creates/validates/destroys TCP sockets |
| `HsmWireMessage` | Value: header + cmdCode + body → toWireBytes() serializer |
| `HsmHeader` | Header config wrapper (length + bytes) |
| `KeyScheme` | hexLenForScheme(U/T/X) → byte count |

### gateway-core

| Class | Role |
|-------|------|
| `CommandDispatcher` | Central dispatcher: vendor→adapter + PoolRouter + audit |
| `PoolRouter` | Selects HsmNode per vendor + lb_strategy |
| `HealthProbeService` | @Scheduled every 15s TCP health probe → updates hsm_node.health |
| `AuditService` | Persists HsmCommandAudit after every dispatch |
| `LoadBalanceStrategy` | Enum: ROUND_ROBIN, WEIGHTED, LEAST_CONN, STICKY_KEY |

### gateway-api

| Class | Role |
|-------|------|
| `ThalesCommandController` | `POST /thales/command/{cmd}` → looks up XxCommandService by code |
| `ThalesCommandService` | Interface: commandCode(), execute(params) → Map |
| `XxCommandService` (×44) | One per Thales command; wraps params into GatewayCommand with correct OpCode |
| `CryptoController` | Semantic `/api/v1/crypto/**` endpoints with typed DTOs |
| `KeyController` | `/api/v1/keys/**` — generate, import, export, list |
| `AuthController` | `/api/v1/auth/**` — login, logout, hash |
| `AdminController` | Banks, branches, HSM pools, nodes, enable/disable/drain |
| `AuditController` | `/api/v1/audit` read-only log |
| `SamController` | `/api/v1/admin/sam/**` — staff, teams, roles, permissions |
| `CryptoService` | Bridge semantic DTOs → GatewayCommand params (familyCodeForKeyType etc) |
| `KeyService` | HSM key lifecycle: generate → persist HsmKey + blob |
| `AuthService` | DB/LDAP/MSAD login, session creation, failed-attempt tracking |
| `SecurityConfig` | Stateless JWT + dev-mode permit-all; OP_* authority injection |
| `JweFilter` | Optional JWE payload encryption/decryption on request/response |

---

## 12. JWE Payload Encryption

Optional layer. When enabled:
- `GET /api/v1/jwe/public-key` returns RSA public key (PEM)
- Client encrypts request body as JWE compact serialization
- `JweFilter` decrypts before routing to controller
- Response re-encrypted before sending back

Used for high-security deployments where TLS alone is not sufficient.

---

## 13. Build & Deploy

```bash
# Build JAR
mvn -T 1C clean package -DskipTests

# Rebuild Docker image
docker compose build --no-cache gateway

# Redeploy (force-recreate keeps Postgres running)
docker compose up -d --force-recreate gateway

# Check logs
docker logs sentinel-hsm-gateway --tail 50

# Health check
curl http://localhost:8090/actuator/health
```

**Default credentials:** `admin` / `sentinel123`  
**Postgres port:** 5434  
**Gateway port:** 8090  

---

## 14. Adding a New Thales Command (Checklist)

1. **`OpCode.java`** — add new enum value
2. **`ThalesCommandCode.java`** — add `XX("XX","XY","Description", specPage)`
3. **`ThalesCmdBuilder.java`** — add `buildXX(HsmHeader, Map<String,Object> params)` and `parseXX(byte[])`
4. **`ThalesVendorAdapter.java`** — add to `SUPPORTED` set, `buildRequest` switch, `expectedResponse` switch
5. **`XxCommandService.java`** — create in `api/command/impl/`; use correct `OpCode`
6. Rebuild + redeploy
7. Test: `POST /thales/command/XX` with correct params

---

## 15. Tested Commands (Live HSM Confirmed err=00)

| Cmd | Test params | Notes |
|-----|-------------|-------|
| NC | `{}` | Network check |
| A0 | `keyType=000 scheme=U` | Generates ZMK; keyType=001=ZPK |
| BU | `keyType=001 scheme=U keyHex=<zmk>` | BU codes: 001=ZMK, 011=ZPK |
| GC | `zmkScheme/zmkHex + zpkScheme/zpkHex` | KCV in response matches A0 KCV |
| A6 | `keyType+zmkUnderLmk+keyUnderZmk+lmkScheme` | Round-trip with GC confirmed |
| A8 | `keyKeyType+zmkUnderLmk+keyUnderLmk+outScheme` | Output matches GC output |

---

## 16. Known Limitations

- HSM simulator (port 7004) only supports: A0, BU, GC, A6, A8, NC — all PIN/CVV/EMV return err=15
- Full PayShield needed to test remaining 37 built-but-untested commands
- BU uses different LMK pair coding than A0 — must use BU-specific keyType codes
- LMK-encrypted blobs are NOT portable across HSMs with different LMKs
- `LEAST_CONN` LB strategy not yet implemented (falls back to index 0)
