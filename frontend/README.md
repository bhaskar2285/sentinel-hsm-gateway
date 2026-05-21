# sentinel-hsm-console

React + Vite + TypeScript + shadcn/ui frontend for `sentinel-hsm-gateway`.

Cosmian KMS-style UI (https://demo-kms.cosmian.dev/ui/locate).

## Pages

- `/login` — JWT auth via xenticate-auth
- `/keys` — locate (search/filter)
- `/keys/new` — create wizard
- `/keys/:id` — detail, export (TR-31/X9.143), rotate
- `/crypto` — encrypt/decrypt/sign/MAC playground
- `/pools` — HSM nodes, health, drain
- `/audit` — command log
- `/admin/rbac` — role/user mgmt
- `/console` — raw cmd (advanced)

## Run

```
bun install
bun run dev
```

Points to `VITE_API_BASE` (default `http://localhost:8080/api/v1`).
