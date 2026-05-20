-- sentinel-hsm-gateway schema V1

CREATE TABLE hsm_pool (
    id              BIGSERIAL PRIMARY KEY,
    vendor          VARCHAR(32)  NOT NULL,
    name            VARCHAR(128) NOT NULL UNIQUE,
    lb_strategy     VARCHAR(32)  NOT NULL DEFAULT 'ROUND_ROBIN',
    kbpk_id         BIGINT,
    enabled         BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE TABLE hsm_node (
    id              BIGSERIAL PRIMARY KEY,
    pool_id         BIGINT       NOT NULL REFERENCES hsm_pool(id),
    vendor          VARCHAR(32)  NOT NULL,
    host            VARCHAR(255) NOT NULL,
    port            INTEGER      NOT NULL,
    weight          INTEGER      NOT NULL DEFAULT 1,
    direction       VARCHAR(16)  NOT NULL DEFAULT 'OUTBOUND',  -- OUTBOUND (gateway dials HSM) | INBOUND (HSM dials gateway)
    enabled         BOOLEAN      NOT NULL DEFAULT TRUE,
    health          VARCHAR(16)  NOT NULL DEFAULT 'UNKNOWN',   -- UP|DOWN|UNKNOWN|DRAINING
    last_seen       TIMESTAMPTZ,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    CONSTRAINT uk_host_port UNIQUE (host, port)
);
CREATE INDEX ix_hsm_node_pool ON hsm_node(pool_id);
CREATE INDEX ix_hsm_node_health ON hsm_node(health);

CREATE TABLE hsm_key (
    id                  BIGSERIAL PRIMARY KEY,
    key_uuid            UUID         NOT NULL UNIQUE,
    label               VARCHAR(255) NOT NULL,
    key_type            VARCHAR(64)  NOT NULL,   -- ZMK, ZPK, TMK, TPK, TAK, KEK, KBPK, BDK, PVK, CVK, MAC, RSA, AES, DES, 3DES, MK-AC, MK-SMI, MK-SMC, MK-DAC, MK-DN, MK-IDN, KMC, ZAK, HMAC, ML-DSA-65, ML-KEM-768
    algo                VARCHAR(32)  NOT NULL,   -- DES|3DES|AES|RSA|HMAC|ML-DSA|ML-KEM
    key_length_bits     INTEGER      NOT NULL,
    usage               VARCHAR(255),            -- comma-list: ENCRYPT,DECRYPT,WRAP,UNWRAP,SIGN,VERIFY,MAC_GEN,MAC_VRFY,PIN_VRFY,KEK
    owner_user_id       VARCHAR(128),
    owner_org           VARCHAR(128),
    kcv                 VARCHAR(16),             -- hex
    encrypted_blob      BYTEA,                   -- vendor-encrypted under LMK
    wrap_key_id         BIGINT       REFERENCES hsm_key(id),
    vendor_origin       VARCHAR(32),             -- thales|utimaco|generated
    lmk_idx             SMALLINT,
    status              VARCHAR(16)  NOT NULL DEFAULT 'ACTIVE', -- ACTIVE|REVOKED|EXPIRED|PENDING|DELETED
    version             INTEGER      NOT NULL DEFAULT 1,
    tags                JSONB,
    created_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    activated_at        TIMESTAMPTZ,
    expires_at          TIMESTAMPTZ,
    revoked_at          TIMESTAMPTZ
);
CREATE INDEX ix_hsm_key_label  ON hsm_key(label);
CREATE INDEX ix_hsm_key_type   ON hsm_key(key_type);
CREATE INDEX ix_hsm_key_owner  ON hsm_key(owner_user_id);
CREATE INDEX ix_hsm_key_status ON hsm_key(status);
CREATE INDEX ix_hsm_key_tags   ON hsm_key USING GIN (tags);

CREATE TABLE hsm_key_block (
    id              BIGSERIAL PRIMARY KEY,
    key_id          BIGINT       NOT NULL REFERENCES hsm_key(id) ON DELETE CASCADE,
    format          VARCHAR(16)  NOT NULL,   -- TR31_B | TR31_D | X9_143 | RAW
    payload         TEXT         NOT NULL,
    kbpk_id         BIGINT       REFERENCES hsm_key(id),
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
CREATE INDEX ix_keyblock_key ON hsm_key_block(key_id);

CREATE TABLE hsm_command_audit (
    id                  BIGSERIAL PRIMARY KEY,
    ts                  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    user_id             VARCHAR(128),
    op                  VARCHAR(64)  NOT NULL,   -- high-level op code (RSA_GEN, DECRYPT...)
    vendor_cmd_code     VARCHAR(8),              -- e.g. "EI"
    key_id              BIGINT,
    pool_id             BIGINT,
    hsm_node_id         BIGINT,
    vendor              VARCHAR(32),
    latency_ms          INTEGER,
    status              VARCHAR(16)  NOT NULL,   -- OK|ERROR|TIMEOUT|REJECTED
    err_code            VARCHAR(16),
    err_text            VARCHAR(512),
    request_hash        VARCHAR(64),
    response_hash       VARCHAR(64),
    trace_id            VARCHAR(64)
);
CREATE INDEX ix_audit_ts    ON hsm_command_audit(ts DESC);
CREATE INDEX ix_audit_user  ON hsm_command_audit(user_id);
CREATE INDEX ix_audit_op    ON hsm_command_audit(op);
CREATE INDEX ix_audit_trace ON hsm_command_audit(trace_id);

CREATE TABLE rbac_role (
    id              BIGSERIAL PRIMARY KEY,
    name            VARCHAR(64)  NOT NULL UNIQUE,
    description     VARCHAR(255),
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE TABLE rbac_role_op (
    role_id         BIGINT       NOT NULL REFERENCES rbac_role(id) ON DELETE CASCADE,
    op              VARCHAR(64)  NOT NULL,
    PRIMARY KEY (role_id, op)
);

CREATE TABLE rbac_user_role (
    user_id         VARCHAR(128) NOT NULL,
    role_id         BIGINT       NOT NULL REFERENCES rbac_role(id) ON DELETE CASCADE,
    granted_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    granted_by      VARCHAR(128),
    PRIMARY KEY (user_id, role_id)
);

-- Seed: default roles
INSERT INTO rbac_role (name, description) VALUES
    ('ADMIN',          'Full access'),
    ('KEY_MANAGER',    'Create/import/export keys'),
    ('CRYPTO_USER',    'Encrypt/decrypt/MAC ops'),
    ('AUDITOR',        'Read-only audit access');

INSERT INTO rbac_role_op (role_id, op)
SELECT id, op FROM rbac_role, (VALUES
    ('KEY_CREATE_RSA'),
    ('KEY_IMPORT'),
    ('KEY_EXPORT'),
    ('KEY_READ'),
    ('CRYPTO_DECRYPT'),
    ('CRYPTO_ENCRYPT'),
    ('MAC_GEN'),
    ('MAC_VRFY'),
    ('PIN_VRFY'),
    ('PIN_XLATE'),
    ('ADMIN_POOL'),
    ('ADMIN_AUDIT'),
    ('RAW_CMD')
) ops(op)
WHERE name = 'ADMIN';

INSERT INTO rbac_role_op (role_id, op)
SELECT id, op FROM rbac_role, (VALUES
    ('KEY_CREATE_RSA'),
    ('KEY_IMPORT'),
    ('KEY_EXPORT'),
    ('KEY_READ')
) ops(op)
WHERE name = 'KEY_MANAGER';

INSERT INTO rbac_role_op (role_id, op)
SELECT id, op FROM rbac_role, (VALUES
    ('CRYPTO_ENCRYPT'),
    ('CRYPTO_DECRYPT'),
    ('MAC_GEN'),
    ('MAC_VRFY'),
    ('KEY_READ')
) ops(op)
WHERE name = 'CRYPTO_USER';

INSERT INTO rbac_role_op (role_id, op)
SELECT id, op FROM rbac_role, (VALUES
    ('ADMIN_AUDIT'),
    ('KEY_READ')
) ops(op)
WHERE name = 'AUDITOR';
