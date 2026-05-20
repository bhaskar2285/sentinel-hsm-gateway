# integration-tests

End-to-end tests against running services.

## Setup
1. Start go-sim HSMs (existing `~/thales-go-sim` or `~/thales-artemis-lb`).
2. Start gateway: `docker compose up -d`.
3. Seed `hsm_pool` and `hsm_node` rows pointing at sim addresses.
4. Get a JWT from xenticate-auth.
5. Run `*.http` scripts (REST client) or `bash` curl tests.

## Smoke
- POST /api/v1/keys/rsa (Phase 1 EI/EJ)
- POST /api/v1/keys/import-rsa-wrapped (GI/GJ)
- POST /api/v1/keys/{id}/export (A8/A9)
- POST /api/v1/crypto/decrypt (M2/M3)
