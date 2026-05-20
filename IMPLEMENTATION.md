# Sentinel HSM Gateway — Implementation Guide

Repos created:
- Backend:  `~/sentinel-hsm-gateway/`
- Frontend: `~/sentinel-hsm-console/`

Verified working as of 2026-05-19:
- Backend boots, schema applies, REST endpoints reachable
- TCP round-trip to thales-go-sim succeeds (vendor responds — wire framing OK)
- Frontend builds (`bun run build` ✓)

---

## 1. Environment

| Item | Value |
|------|-------|
| Java | 25.0.2 (Temurin) |
| Maven | 3.8.7 |
| Spring Boot | 3.5.0 |
| Lombok | 1.18.42 (Java 25 support) |
| Postgres | 16-alpine (docker) |
| Node | bun (Vite + React + TS) |
| Existing infra in use | postgres-primary, lb-1..4, hsm-sim-1..2, thales-go-sim |

### Ports

| Service | Host port | Container port | Notes |
|---------|-----------|----------------|-------|
| sentinel-postgres | 5434 | 5432 | new (5433 occupied by postgres-primary) |
| sentinel-hsm-gateway | 8090 | 8080 | new (8080 occupied by backend-1) |
| hsm-sim-1 (Thales) | 19000 | 9000 | existing |
| thales-go-sim | 19998 | 9998 | existing |
| postgres-primary | 5433 | 5432 | existing — unrelated |

---

## 2. Build

```bash
cd ~/sentinel-hsm-gateway
mvn -B -T 1C -DskipTests clean install
```

Output: `modules/gateway-api/target/sentinel-hsm-gateway.jar` (~78 MB fat jar)

### Build fixes applied
- Lombok 1.18.34 → **1.18.42** — Java 25 compiler `TypeTag::UNKNOWN` fix
- `pool.invalidateObject(s)` wrapped in try/catch — declares `Exception`
- Removed `@WithMockUser` from SmokeIT — needs `spring-security-test` not pulled
- `@Lob byte[]` → `@Column(columnDefinition="bytea")` — Hibernate 6 default is OID
- Wire framing **2-byte length prefix** (not 4) — native payShield protocol
- `DataInputStream.readUnsignedShort()` — match 2-byte length on read
- Dockerfile UID 1000 → **1500** — host UID 1000 collision

---

## 3. Start services

### 3.1 Docker compose
```bash
cd ~/sentinel-hsm-gateway
docker compose up -d --build
```
Spins up:
- `sentinel-postgres` on host:5434
- `sentinel-hsm-gateway` on host:8090

Flyway runs V1 automatically on boot. Schema:
```
hsm_pool, hsm_node, hsm_key, hsm_key_block,
hsm_command_audit, rbac_role, rbac_role_op, rbac_user_role
```
Seed: 4 default roles (ADMIN/KEY_MANAGER/CRYPTO_USER/AUDITOR) with op grants.

### 3.2 Verify boot
```bash
curl http://localhost:8090/actuator/health     # {"status":"UP"}
curl http://localhost:8090/v3/api-docs         # OpenAPI JSON
curl http://localhost:8090/swagger-ui.html     # Swagger UI
```

---

## 4. Seed pool + nodes

Tells gateway where HSMs are. Empty `hsm_node` = every cmd fails `NN: No healthy HSM node`.

```bash
docker exec sentinel-postgres psql -U sentinel -d sentinel <<SQL
INSERT INTO hsm_pool (vendor, name, lb_strategy, enabled)
VALUES ('THALES', 'thales-primary', 'ROUND_ROBIN', true);

INSERT INTO hsm_node (pool_id, vendor, host, port, weight, direction, enabled, health)
VALUES
  (1, 'THALES', 'host.docker.internal', 19000, 1, 'OUTBOUND', true, 'UNKNOWN'),
  (1, 'THALES', 'host.docker.internal', 19998, 1, 'OUTBOUND', true, 'UNKNOWN');
SQL
```

**Why these ports**: `host.docker.internal:19000` reaches host's `hsm-sim-1` (mapped 9000→19000). 19998 is `thales-go-sim`. The gateway opens TCP socket and sends 2-byte length-prefixed Thales commands.

`host.docker.internal:host-gateway` added in compose `extra_hosts` lets container reach host network.

---

## 5. Auth — dev mode (no JWT yet)

xenticate-auth integration TBD. Backend runs `SPRING_PROFILES_ACTIVE=dev` which:
- Disables OAuth2 resource server
- `anonymous()` user granted all `OP_*` authorities → `@PreAuthorize` passes
- All `@AuthenticationPrincipal Jwt jwt` replaced with `Authentication auth` → `auth == null ? "anonymous" : auth.getName()`

### Switch to prod JWT later
```bash
SPRING_PROFILES_ACTIVE=prod \
OAUTH_ISSUER=https://xenticate-auth.example.com/realms/sentinel \
docker compose up -d
```
- Spring Security auto-fetches JWKS from `${OAUTH_ISSUER}/.well-known/openid-configuration`
- `RbacJwtConverter` reads `sub` claim → joins `rbac_user_role` → `rbac_role_op` → emits `OP_*` authorities
- Grant users via `INSERT INTO rbac_user_role (user_id, role_id) VALUES ('alice@x.com', 1)`

---

## 6. Phase 1 endpoint tests

### 6.1 RSA key gen (EI/EJ)
```bash
curl -X POST http://localhost:8090/api/v1/keys/rsa \
  -H "Content-Type: application/json" \
  -d '{
    "label": "test-rsa-2048",
    "modulusBits": 2048,
    "keyType": "2",
    "publicExponentHex": "010001",
    "usage": "WRAP,UNWRAP"
  }'
```

Response shape:
```json
{"keyId":"<uuid>","publicKey":"...","kcv":"...","status":"OK",
 "errCode":"00","errText":"No error","latencyMs":42}
```

Current sim returns `errCode: 98` — wire framing works (2-byte length OK), but Phase1Builder EI body layout needs refinement against payShield spec p.167. Phase1 next iteration.

### 6.2 List keys
```bash
curl http://localhost:8090/api/v1/keys
curl http://localhost:8090/api/v1/keys?label=test
```

### 6.3 Get pools / nodes
```bash
curl http://localhost:8090/api/v1/pools
curl http://localhost:8090/api/v1/hsms
curl -X POST http://localhost:8090/api/v1/hsms/1/drain   # admin
```

### 6.4 Import RSA-wrapped key (GI/GJ)
```bash
curl -X POST http://localhost:8090/api/v1/keys/import-rsa-wrapped \
  -H "Content-Type: application/json" \
  -d '{"label":"imported","wrappingPublicKey":"30...","wrappedKey":"AB...","hashId":"01"}'
```

### 6.5 Export key (A8/A9)
```bash
curl -X POST http://localhost:8090/api/v1/keys/<uuid>/export \
  -H "Content-Type: application/json" \
  -d '{"format":"TR31_D","kekType":"0"}'
```

### 6.6 Decrypt (M2/M3)
```bash
curl -X POST http://localhost:8090/api/v1/crypto/decrypt \
  -H "Content-Type: application/json" \
  -d '{"keyId":"<uuid>","ciphertextHex":"AABB...","mode":"01","iv":"0000000000000000"}'
```

---

## 7. Frontend

```bash
cd ~/sentinel-hsm-console
bun install
bun run dev          # http://localhost:5174
# or:
bun run build && npx serve dist
```

Vite proxies `/api/*` to `http://localhost:8080` by default. Override via:
```bash
VITE_API_TARGET=http://localhost:8090 bun run dev
```

Or rely on the axios `baseURL` env:
```bash
VITE_API_BASE=http://localhost:8090/api/v1 bun run dev
```

### Pages
- `/login` — paste JWT (dev mode: paste anything, ignored)
- `/keys` — Locate (search by label/type)
- `/keys/new` — Generate RSA wizard
- `/keys/:id` — Detail + Export (TR-31 B/D, X9.143, RAW)
- `/crypto` — Decrypt playground
- `/pools` — Pool + node dashboard
- `/audit`, `/console`, `/admin/rbac` — Phase 2

---

## 8. Architecture map

```
        REST (HTTP/JSON)
              │
   ┌──────────▼──────────┐
   │   gateway-api       │  SpringBoot main, controllers, DTOs
   └──────────┬──────────┘
              │
   ┌──────────▼──────────┐
   │   gateway-security  │  JWT validator (prod) / anon-all (dev), @PreAuthorize
   └──────────┬──────────┘
              │
   ┌──────────▼──────────┐
   │   gateway-core      │  CommandDispatcher, PoolRouter, AuditService
   └──┬───────┬──────────┘
      │       │
      │       │
   ┌──▼──┐ ┌──▼─────────────────┐
   │SPI  │ │gateway-persistence │  Flyway, JPA entities, repos
   └─┬───┘ └────────────────────┘
     │
   ┌─▼───────────────────┐ ┌─────────────────────┐
   │vendor-thales        │ │vendor-utimaco (stub)│
   │  Phase1Builder      │ │                     │
   │  Phase1Parser       │ │                     │
   │  ThalesTransport    │ │                     │
   └─┬───────────────────┘ └─────────────────────┘
     │  TCP, 2-byte length + cmd + body
   ┌─▼───────────────────────────────────────┐
   │ Thales HSM / payShield 10K / go-sim     │
   └─────────────────────────────────────────┘

Existing thales-artemis-lb untouched.
HSM nodes registered in DB → PoolRouter picks one (RR/weighted/sticky).
```

---

## 9. Operational commands

| Action | Command |
|--------|---------|
| Build | `mvn -T 1C -DskipTests clean install` |
| Up   | `docker compose up -d --build` |
| Down | `docker compose down` |
| Reset DB | `docker compose down -v && docker compose up -d` |
| Logs | `docker logs -f sentinel-hsm-gateway` |
| Shell DB | `docker exec -it sentinel-postgres psql -U sentinel sentinel` |
| Rebuild only gateway | `docker compose up -d --build gateway` |
| Frontend dev | `cd ~/sentinel-hsm-console && bun run dev` |
| Frontend build | `bun run build && ls dist/` |

---

## 10. Known TODO / Phase 2 backlog

### Recently completed (session 2026-05-20)
- ✅ Wire-level visibility (sim `HSM_TRACE=1` hex+ascii dump)
- ✅ V2 migration drafted — ISC 15-col audit template + `isc_ms_bank` + `isc_ms_branch`
- ✅ V3 migration drafted — full ISC SAM RBAC (drops legacy `rbac_*`)
- ✅ xenticate-auth → sentinel JWT integration (login frontend + API)
- ✅ Frontend KBPK dropdown wired (filters ZMK/KBPK/TMK)

### Phase 1 polish — REMAINING
1. **KBPK full implementation (priority)** — `gateway-keyblock/Tr31Codec.java` + `X9143Codec.java` exist but **not wired** into `ThalesVendorAdapter.execute(KEY_EXPORT)`. Need:
   - Invoke `Tr31Codec.encode(keyBytes, kbpkKey, header)` from adapter
   - CMAC binding over header + payload using KBPK
   - Header attributes mapped (key-usage, algo, mode, exportability, version)
   - Drop A8-binary fallback, return real ASCII key block (`D0144B0TB00N00…`)
   - Dual-control approval gate on `KEY_EXPORT` op
   - KCV of KBPK verified pre-export
2. **EI/GI/A8/M2 body field layouts** — verify vs payShield 10K Host Programmer's Manual spec pages 167, 182, 59, 384.
3. **EJ/GJ/A9/M3 response parsers** — currently store body as `raw` for GJ/A9. Implement exact field decoding.
4. **KCV computation** in KeyService after EI success (call `Tr31Codec.kcv()`).
5. **Health probe NC** — `ThalesVendorAdapter.health()` uses bare "NC"; verify against spec.
6. **Apply V2 + V3 migrations** to running DB (rebuild + restart gateway, watch Flyway log).
7. **Backfill `isc_ms_bank` FK** on existing keys — UPDATE `hsm_key.bank_rec_id` after V2 from existing `owner_org`.

### Phase 2 (next milestone)
- LDAP / MSAD auth wiring (Spring LDAP). Schema ready in `isc_ms_bank.login_method_type` + ldap_ip/port/base_dn. Need `AuthStrategyFactory` per-bank.
- V4 migration: `isc_sam_login_audit` + mTLS cert auth columns.
- Java JPA entities for `isc_ms_bank`, `isc_ms_branch`, `isc_sam_*` (replace legacy `RbacRole`).
- REST endpoints: `/api/v1/admin/banks`, `/api/v1/admin/branches`, `/api/v1/admin/sam/*`.
- Frontend: Bank/Branch admin pages, SAM role/team/staff CRUD, login audit viewer.
- Remaining ~165 Thales 2-letter commands (PIN ops, MAC, EMV, key mgmt, RSA full, etc.)
- Utimaco adapter real impl
- Inbound HSM listener (HSM dials gateway — config `direction=INBOUND` in `hsm_node`)
- Resilience4j circuit breaker per pool
- `/api/v1/audit` REST search endpoint with FI/branch/staff filters
- `/api/v1/raw` advanced passthrough
- Sticky-key LB strategy (currently round-robin only is wired)
- Metrics → Prometheus (`/actuator/prometheus` already exposed)
- Frontend: Audit search page, raw cmd console
- TLS for HSM TCP (payShield SSL/TLS mode)
- Wire-trace persistence (V5): `req_hex`/`resp_hex` columns on `hsm_command_audit` + `/audit/{keyId}/trace` endpoint + KeyDetail Wire Trace tab

---

## 11. Quick verification checklist

After fresh checkout:
```bash
cd ~/sentinel-hsm-gateway
mvn -T 1C -DskipTests clean install                           # backend builds
docker compose up -d --build                                  # services up
sleep 15
curl -s http://localhost:8090/actuator/health                 # → {"status":"UP"}
docker exec sentinel-postgres psql -U sentinel sentinel \
  -c "SELECT name FROM rbac_role;"                            # → 4 roles
curl -s http://localhost:8090/api/v1/keys                     # → []

cd ~/sentinel-hsm-console
bun install && bun run build                                  # frontend builds
bun run dev                                                   # → http://localhost:5174
```
