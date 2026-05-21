-- =====================================================================
-- sentinel-hsm-gateway schema V3
-- Replaces legacy rbac_role / rbac_role_op / rbac_user_role with full
-- ISC SAM (Security Access Management) schema adopted from
-- xenticate-liquibase/04-sam_schema.xml.
--
-- Model:
--   bank ─< team ─< staff
--          └────────< staff_branch ──> branch
--   bank ─< role ─< accesscontrol >── menu ─< menu_action >── action
--          team_role  binds  team ↔ role
--   session tracks live logins
-- =====================================================================

-- ---------------------------------------------------------------------
-- 0. Drop legacy RBAC tables (replaced by isc_sam_*)
-- ---------------------------------------------------------------------
DROP TABLE IF EXISTS rbac_user_role;
DROP TABLE IF EXISTS rbac_role_op;
DROP TABLE IF EXISTS rbac_role;

-- ---------------------------------------------------------------------
-- 1. isc_sam_action — verb catalog
-- ---------------------------------------------------------------------
CREATE TABLE isc_sam_action (
    rec_id                      BIGSERIAL    PRIMARY KEY,
    name                        VARCHAR(50)  NOT NULL UNIQUE,                -- KEY_CREATE_RSA, KEY_EXPORT, CRYPTO_DECRYPT…
    description                 VARCHAR(255),
    record_status               CHAR(1)      NOT NULL DEFAULT 'Y',
    record_created_date         TIMESTAMP    NOT NULL DEFAULT NOW(),
    record_created_id           INTEGER      NOT NULL DEFAULT 0,
    record_created_name         VARCHAR(50)  NOT NULL DEFAULT 'SYSTEM',
    record_created_team_code    VARCHAR(20)  NOT NULL DEFAULT 'SYSTEM',
    record_created_team_name    VARCHAR(50)  NOT NULL DEFAULT 'SYSTEM',
    record_created_bank_code    VARCHAR(20)  NOT NULL DEFAULT 'ISC',
    record_created_bank_name    VARCHAR(50)  NOT NULL DEFAULT 'ISC',
    record_updated_date         TIMESTAMP    NOT NULL DEFAULT NOW(),
    record_updated_id           INTEGER      NOT NULL DEFAULT 0,
    record_updated_name         VARCHAR(50)  NOT NULL DEFAULT 'SYSTEM',
    record_updated_team_code    VARCHAR(20)  NOT NULL DEFAULT 'SYSTEM',
    record_updated_team_name    VARCHAR(50)  NOT NULL DEFAULT 'SYSTEM',
    record_updated_bank_code    VARCHAR(20)  NOT NULL DEFAULT 'ISC',
    record_updated_bank_name    VARCHAR(50)  NOT NULL DEFAULT 'ISC'
);

-- ---------------------------------------------------------------------
-- 2. isc_sam_menu — feature/screen catalog
-- ---------------------------------------------------------------------
CREATE TABLE isc_sam_menu (
    rec_id                      BIGSERIAL    PRIMARY KEY,
    ms_bank_id                  BIGINT       NOT NULL REFERENCES isc_ms_bank(rec_id) ON DELETE RESTRICT,
    menu_name                   VARCHAR(50)  NOT NULL,                       -- KEY_MGMT, EXPORT, DECRYPT, AUDIT, RBAC…
    display_name                VARCHAR(100),
    parent_menu                 BIGINT       REFERENCES isc_sam_menu(rec_id),
    url                         VARCHAR(1000),
    target                      VARCHAR(50),
    position                    INTEGER,
    sort_order                  INTEGER,
    record_status               CHAR(1)      NOT NULL DEFAULT 'Y',
    record_created_date         TIMESTAMP    NOT NULL DEFAULT NOW(),
    record_created_id           INTEGER      NOT NULL DEFAULT 0,
    record_created_name         VARCHAR(50)  NOT NULL DEFAULT 'SYSTEM',
    record_created_team_code    VARCHAR(20)  NOT NULL DEFAULT 'SYSTEM',
    record_created_team_name    VARCHAR(50)  NOT NULL DEFAULT 'SYSTEM',
    record_created_bank_code    VARCHAR(20)  NOT NULL DEFAULT 'ISC',
    record_created_bank_name    VARCHAR(50)  NOT NULL DEFAULT 'ISC',
    record_updated_date         TIMESTAMP    NOT NULL DEFAULT NOW(),
    record_updated_id           INTEGER      NOT NULL DEFAULT 0,
    record_updated_name         VARCHAR(50)  NOT NULL DEFAULT 'SYSTEM',
    record_updated_team_code    VARCHAR(20)  NOT NULL DEFAULT 'SYSTEM',
    record_updated_team_name    VARCHAR(50)  NOT NULL DEFAULT 'SYSTEM',
    record_updated_bank_code    VARCHAR(20)  NOT NULL DEFAULT 'ISC',
    record_updated_bank_name    VARCHAR(50)  NOT NULL DEFAULT 'ISC'
);
CREATE INDEX ix_sam_menu_bank ON isc_sam_menu(ms_bank_id);

-- ---------------------------------------------------------------------
-- 3. isc_sam_menu_action — junction: which actions allowed per menu
-- ---------------------------------------------------------------------
CREATE TABLE isc_sam_menu_action (
    rec_id                      BIGSERIAL    PRIMARY KEY,
    sam_menu_id                 BIGINT       NOT NULL REFERENCES isc_sam_menu(rec_id)   ON DELETE CASCADE,
    sam_action_id               BIGINT       NOT NULL REFERENCES isc_sam_action(rec_id) ON DELETE CASCADE,
    record_status               CHAR(1)      NOT NULL DEFAULT 'Y',
    record_created_date         TIMESTAMP    NOT NULL DEFAULT NOW(),
    record_created_id           INTEGER      NOT NULL DEFAULT 0,
    record_created_name         VARCHAR(50)  NOT NULL DEFAULT 'SYSTEM',
    record_created_team_code    VARCHAR(20)  NOT NULL DEFAULT 'SYSTEM',
    record_created_team_name    VARCHAR(50)  NOT NULL DEFAULT 'SYSTEM',
    record_created_bank_code    VARCHAR(20)  NOT NULL DEFAULT 'ISC',
    record_created_bank_name    VARCHAR(50)  NOT NULL DEFAULT 'ISC',
    record_updated_date         TIMESTAMP    NOT NULL DEFAULT NOW(),
    record_updated_id           INTEGER      NOT NULL DEFAULT 0,
    record_updated_name         VARCHAR(50)  NOT NULL DEFAULT 'SYSTEM',
    record_updated_team_code    VARCHAR(20)  NOT NULL DEFAULT 'SYSTEM',
    record_updated_team_name    VARCHAR(50)  NOT NULL DEFAULT 'SYSTEM',
    record_updated_bank_code    VARCHAR(20)  NOT NULL DEFAULT 'ISC',
    record_updated_bank_name    VARCHAR(50)  NOT NULL DEFAULT 'ISC',
    CONSTRAINT uk_sam_menu_action UNIQUE (sam_menu_id, sam_action_id)
);

-- ---------------------------------------------------------------------
-- 4. isc_sam_menu_link — sidebar / nav URLs per bank
-- ---------------------------------------------------------------------
CREATE TABLE isc_sam_menu_link (
    rec_id                      BIGSERIAL    PRIMARY KEY,
    ms_bank_id                  BIGINT       NOT NULL REFERENCES isc_ms_bank(rec_id) ON DELETE RESTRICT,
    screen_main_name            VARCHAR(50)  NOT NULL,
    screen_link_name            VARCHAR(50)  NOT NULL,
    screen_link_url             VARCHAR(1000) NOT NULL,
    link_sort                   VARCHAR(20)  NOT NULL,
    record_status               CHAR(1)      NOT NULL DEFAULT 'Y',
    record_created_date         TIMESTAMP    NOT NULL DEFAULT NOW(),
    record_created_id           INTEGER      NOT NULL DEFAULT 0,
    record_created_name         VARCHAR(50)  NOT NULL DEFAULT 'SYSTEM',
    record_created_team_code    VARCHAR(20)  NOT NULL DEFAULT 'SYSTEM',
    record_created_team_name    VARCHAR(50)  NOT NULL DEFAULT 'SYSTEM',
    record_created_bank_code    VARCHAR(20)  NOT NULL DEFAULT 'ISC',
    record_created_bank_name    VARCHAR(50)  NOT NULL DEFAULT 'ISC',
    record_updated_date         TIMESTAMP    NOT NULL DEFAULT NOW(),
    record_updated_id           INTEGER      NOT NULL DEFAULT 0,
    record_updated_name         VARCHAR(50)  NOT NULL DEFAULT 'SYSTEM',
    record_updated_team_code    VARCHAR(20)  NOT NULL DEFAULT 'SYSTEM',
    record_updated_team_name    VARCHAR(50)  NOT NULL DEFAULT 'SYSTEM',
    record_updated_bank_code    VARCHAR(20)  NOT NULL DEFAULT 'ISC',
    record_updated_bank_name    VARCHAR(50)  NOT NULL DEFAULT 'ISC'
);

-- ---------------------------------------------------------------------
-- 5. isc_sam_role — roles scoped per bank
-- ---------------------------------------------------------------------
CREATE TABLE isc_sam_role (
    rec_id                      BIGSERIAL    PRIMARY KEY,
    ms_bank_id                  BIGINT       NOT NULL REFERENCES isc_ms_bank(rec_id) ON DELETE RESTRICT,
    role_name                   VARCHAR(50)  NOT NULL,
    description                 VARCHAR(255),
    record_status               CHAR(1)      NOT NULL DEFAULT 'Y',
    record_created_date         TIMESTAMP    NOT NULL DEFAULT NOW(),
    record_created_id           INTEGER      NOT NULL DEFAULT 0,
    record_created_name         VARCHAR(50)  NOT NULL DEFAULT 'SYSTEM',
    record_created_team_code    VARCHAR(20)  NOT NULL DEFAULT 'SYSTEM',
    record_created_team_name    VARCHAR(50)  NOT NULL DEFAULT 'SYSTEM',
    record_created_bank_code    VARCHAR(20)  NOT NULL DEFAULT 'ISC',
    record_created_bank_name    VARCHAR(50)  NOT NULL DEFAULT 'ISC',
    record_updated_date         TIMESTAMP    NOT NULL DEFAULT NOW(),
    record_updated_id           INTEGER      NOT NULL DEFAULT 0,
    record_updated_name         VARCHAR(50)  NOT NULL DEFAULT 'SYSTEM',
    record_updated_team_code    VARCHAR(20)  NOT NULL DEFAULT 'SYSTEM',
    record_updated_team_name    VARCHAR(50)  NOT NULL DEFAULT 'SYSTEM',
    record_updated_bank_code    VARCHAR(20)  NOT NULL DEFAULT 'ISC',
    record_updated_bank_name    VARCHAR(50)  NOT NULL DEFAULT 'ISC',
    CONSTRAINT uk_sam_role UNIQUE (ms_bank_id, role_name)
);

-- ---------------------------------------------------------------------
-- 6. isc_sam_accesscontrol — role × menu × action (the actual permission)
-- ---------------------------------------------------------------------
CREATE TABLE isc_sam_accesscontrol (
    rec_id                      BIGSERIAL    PRIMARY KEY,
    sam_role_id                 BIGINT       NOT NULL REFERENCES isc_sam_role(rec_id)   ON DELETE CASCADE,
    sam_menu_id                 BIGINT       NOT NULL REFERENCES isc_sam_menu(rec_id)   ON DELETE CASCADE,
    sam_action_id               BIGINT       NOT NULL REFERENCES isc_sam_action(rec_id) ON DELETE CASCADE,
    record_status               CHAR(1)      NOT NULL DEFAULT 'Y',
    record_created_date         TIMESTAMP    NOT NULL DEFAULT NOW(),
    record_created_id           INTEGER      NOT NULL DEFAULT 0,
    record_created_name         VARCHAR(50)  NOT NULL DEFAULT 'SYSTEM',
    record_created_team_code    VARCHAR(20)  NOT NULL DEFAULT 'SYSTEM',
    record_created_team_name    VARCHAR(50)  NOT NULL DEFAULT 'SYSTEM',
    record_created_bank_code    VARCHAR(20)  NOT NULL DEFAULT 'ISC',
    record_created_bank_name    VARCHAR(50)  NOT NULL DEFAULT 'ISC',
    record_updated_date         TIMESTAMP    NOT NULL DEFAULT NOW(),
    record_updated_id           INTEGER      NOT NULL DEFAULT 0,
    record_updated_name         VARCHAR(50)  NOT NULL DEFAULT 'SYSTEM',
    record_updated_team_code    VARCHAR(20)  NOT NULL DEFAULT 'SYSTEM',
    record_updated_team_name    VARCHAR(50)  NOT NULL DEFAULT 'SYSTEM',
    record_updated_bank_code    VARCHAR(20)  NOT NULL DEFAULT 'ISC',
    record_updated_bank_name    VARCHAR(50)  NOT NULL DEFAULT 'ISC',
    CONSTRAINT uk_sam_access UNIQUE (sam_role_id, sam_menu_id, sam_action_id)
);
CREATE INDEX ix_sam_access_role ON isc_sam_accesscontrol(sam_role_id);

-- ---------------------------------------------------------------------
-- 7. isc_sam_team — teams per bank
-- ---------------------------------------------------------------------
CREATE TABLE isc_sam_team (
    rec_id                      BIGSERIAL    PRIMARY KEY,
    ms_bank_id                  BIGINT       NOT NULL REFERENCES isc_ms_bank(rec_id) ON DELETE RESTRICT,
    team_code                   VARCHAR(20)  NOT NULL,
    team_name                   VARCHAR(50)  NOT NULL,
    record_status               CHAR(1)      NOT NULL DEFAULT 'Y',
    record_created_date         TIMESTAMP    NOT NULL DEFAULT NOW(),
    record_created_id           INTEGER      NOT NULL DEFAULT 0,
    record_created_name         VARCHAR(50)  NOT NULL DEFAULT 'SYSTEM',
    record_created_team_code    VARCHAR(20)  NOT NULL DEFAULT 'SYSTEM',
    record_created_team_name    VARCHAR(50)  NOT NULL DEFAULT 'SYSTEM',
    record_created_bank_code    VARCHAR(20)  NOT NULL DEFAULT 'ISC',
    record_created_bank_name    VARCHAR(50)  NOT NULL DEFAULT 'ISC',
    record_updated_date         TIMESTAMP    NOT NULL DEFAULT NOW(),
    record_updated_id           INTEGER      NOT NULL DEFAULT 0,
    record_updated_name         VARCHAR(50)  NOT NULL DEFAULT 'SYSTEM',
    record_updated_team_code    VARCHAR(20)  NOT NULL DEFAULT 'SYSTEM',
    record_updated_team_name    VARCHAR(50)  NOT NULL DEFAULT 'SYSTEM',
    record_updated_bank_code    VARCHAR(20)  NOT NULL DEFAULT 'ISC',
    record_updated_bank_name    VARCHAR(50)  NOT NULL DEFAULT 'ISC',
    CONSTRAINT uk_sam_team UNIQUE (ms_bank_id, team_code)
);

-- ---------------------------------------------------------------------
-- 8. isc_sam_team_role — team × role
-- ---------------------------------------------------------------------
CREATE TABLE isc_sam_team_role (
    rec_id                      BIGSERIAL    PRIMARY KEY,
    sam_team_id                 BIGINT       NOT NULL REFERENCES isc_sam_team(rec_id) ON DELETE CASCADE,
    sam_role_id                 BIGINT       NOT NULL REFERENCES isc_sam_role(rec_id) ON DELETE CASCADE,
    record_status               CHAR(1)      NOT NULL DEFAULT 'Y',
    record_created_date         TIMESTAMP    NOT NULL DEFAULT NOW(),
    record_created_id           INTEGER      NOT NULL DEFAULT 0,
    record_created_name         VARCHAR(50)  NOT NULL DEFAULT 'SYSTEM',
    record_created_team_code    VARCHAR(20)  NOT NULL DEFAULT 'SYSTEM',
    record_created_team_name    VARCHAR(50)  NOT NULL DEFAULT 'SYSTEM',
    record_created_bank_code    VARCHAR(20)  NOT NULL DEFAULT 'ISC',
    record_created_bank_name    VARCHAR(50)  NOT NULL DEFAULT 'ISC',
    record_updated_date         TIMESTAMP    NOT NULL DEFAULT NOW(),
    record_updated_id           INTEGER      NOT NULL DEFAULT 0,
    record_updated_name         VARCHAR(50)  NOT NULL DEFAULT 'SYSTEM',
    record_updated_team_code    VARCHAR(20)  NOT NULL DEFAULT 'SYSTEM',
    record_updated_team_name    VARCHAR(50)  NOT NULL DEFAULT 'SYSTEM',
    record_updated_bank_code    VARCHAR(20)  NOT NULL DEFAULT 'ISC',
    record_updated_bank_name    VARCHAR(50)  NOT NULL DEFAULT 'ISC',
    CONSTRAINT uk_sam_team_role UNIQUE (sam_team_id, sam_role_id)
);

-- ---------------------------------------------------------------------
-- 9. isc_sam_staff — user account
-- ---------------------------------------------------------------------
CREATE TABLE isc_sam_staff (
    rec_id                      BIGSERIAL    PRIMARY KEY,
    staff_fname                 VARCHAR(50)  NOT NULL,
    staff_lname                 VARCHAR(50)  NOT NULL,
    staff_email                 VARCHAR(255),
    ms_bank_id                  BIGINT       NOT NULL REFERENCES isc_ms_bank(rec_id)   ON DELETE RESTRICT,
    ms_branch_id                BIGINT                REFERENCES isc_ms_branch(rec_id) ON DELETE RESTRICT,
    sam_team_id                 BIGINT       NOT NULL REFERENCES isc_sam_team(rec_id)  ON DELETE RESTRICT,
    staff_loginname             VARCHAR(64)  NOT NULL UNIQUE,
    staff_loginpwd              VARCHAR(1024),                                          -- bcrypt or LDAP-bind (nullable for LDAP)
    last_updated_loginpwd       VARCHAR(8),
    bad_loginpwd_count          INTEGER      NOT NULL DEFAULT 0,
    user_status_code            VARCHAR(20)  NOT NULL DEFAULT 'ACTIVE',                 -- ACTIVE|LOCKED|INACTIVE|EXPIRED
    activated_date_time         TIMESTAMP,
    inactivated_date_time       TIMESTAMP,
    locked_date_time            TIMESTAMP,
    expiried_date_time          TIMESTAMP,
    last_login_date_time        TIMESTAMP,
    employee_code               VARCHAR(20),
    ms_department1_id           INTEGER,
    ms_department2_id           INTEGER,
    ms_department3_id           INTEGER,
    force_change_pwd_flag       CHAR(1)      NOT NULL DEFAULT 'N',
    lk_otp_type_code            VARCHAR(20),
    otp_no                      VARCHAR(1024),
    record_status               CHAR(1)      NOT NULL DEFAULT 'Y',
    record_created_date         TIMESTAMP    NOT NULL DEFAULT NOW(),
    record_created_id           INTEGER      NOT NULL DEFAULT 0,
    record_created_name         VARCHAR(50)  NOT NULL DEFAULT 'SYSTEM',
    record_created_team_code    VARCHAR(20)  NOT NULL DEFAULT 'SYSTEM',
    record_created_team_name    VARCHAR(50)  NOT NULL DEFAULT 'SYSTEM',
    record_created_bank_code    VARCHAR(20)  NOT NULL DEFAULT 'ISC',
    record_created_bank_name    VARCHAR(50)  NOT NULL DEFAULT 'ISC',
    record_updated_date         TIMESTAMP    NOT NULL DEFAULT NOW(),
    record_updated_id           INTEGER      NOT NULL DEFAULT 0,
    record_updated_name         VARCHAR(50)  NOT NULL DEFAULT 'SYSTEM',
    record_updated_team_code    VARCHAR(20)  NOT NULL DEFAULT 'SYSTEM',
    record_updated_team_name    VARCHAR(50)  NOT NULL DEFAULT 'SYSTEM',
    record_updated_bank_code    VARCHAR(20)  NOT NULL DEFAULT 'ISC',
    record_updated_bank_name    VARCHAR(50)  NOT NULL DEFAULT 'ISC'
);
CREATE INDEX ix_sam_staff_bank   ON isc_sam_staff(ms_bank_id);
CREATE INDEX ix_sam_staff_team   ON isc_sam_staff(sam_team_id);
CREATE INDEX ix_sam_staff_status ON isc_sam_staff(user_status_code);

-- ---------------------------------------------------------------------
-- 10. isc_sam_staff_branch — staff posting at branches
-- ---------------------------------------------------------------------
CREATE TABLE isc_sam_staff_branch (
    rec_id                      BIGSERIAL    PRIMARY KEY,
    sam_staff_id                BIGINT       NOT NULL REFERENCES isc_sam_staff(rec_id)   ON DELETE CASCADE,
    ms_branch_id                BIGINT       NOT NULL REFERENCES isc_ms_branch(rec_id)   ON DELETE RESTRICT,
    is_primary                  CHAR(1)      NOT NULL DEFAULT 'N',
    record_status               CHAR(1)      NOT NULL DEFAULT 'Y',
    record_created_date         TIMESTAMP    NOT NULL DEFAULT NOW(),
    record_created_id           INTEGER      NOT NULL DEFAULT 0,
    record_created_name         VARCHAR(50)  NOT NULL DEFAULT 'SYSTEM',
    record_created_team_code    VARCHAR(20)  NOT NULL DEFAULT 'SYSTEM',
    record_created_team_name    VARCHAR(50)  NOT NULL DEFAULT 'SYSTEM',
    record_created_bank_code    VARCHAR(20)  NOT NULL DEFAULT 'ISC',
    record_created_bank_name    VARCHAR(50)  NOT NULL DEFAULT 'ISC',
    record_updated_date         TIMESTAMP    NOT NULL DEFAULT NOW(),
    record_updated_id           INTEGER      NOT NULL DEFAULT 0,
    record_updated_name         VARCHAR(50)  NOT NULL DEFAULT 'SYSTEM',
    record_updated_team_code    VARCHAR(20)  NOT NULL DEFAULT 'SYSTEM',
    record_updated_team_name    VARCHAR(50)  NOT NULL DEFAULT 'SYSTEM',
    record_updated_bank_code    VARCHAR(20)  NOT NULL DEFAULT 'ISC',
    record_updated_bank_name    VARCHAR(50)  NOT NULL DEFAULT 'ISC',
    CONSTRAINT uk_sam_staff_branch UNIQUE (sam_staff_id, ms_branch_id)
);

-- ---------------------------------------------------------------------
-- 11. isc_sam_session — live login sessions
-- ---------------------------------------------------------------------
CREATE TABLE isc_sam_session (
    rec_id                      BIGSERIAL    PRIMARY KEY,
    sam_staff_id                BIGINT       NOT NULL REFERENCES isc_sam_staff(rec_id) ON DELETE CASCADE,
    session_token               VARCHAR(255) NOT NULL UNIQUE,                -- JWT ID / opaque session id
    ip_address                  VARCHAR(45),                                  -- v4/v6
    user_agent                  VARCHAR(512),
    login_at                    TIMESTAMP    NOT NULL DEFAULT NOW(),
    last_seen_at                TIMESTAMP    NOT NULL DEFAULT NOW(),
    expires_at                  TIMESTAMP    NOT NULL,
    logout_at                   TIMESTAMP,
    record_status               CHAR(1)      NOT NULL DEFAULT 'Y'
);
CREATE INDEX ix_sam_session_staff   ON isc_sam_session(sam_staff_id);
CREATE INDEX ix_sam_session_expires ON isc_sam_session(expires_at);

-- ---------------------------------------------------------------------
-- 12. Triggers for record_updated_date
-- ---------------------------------------------------------------------
CREATE TRIGGER trg_touch_sam_action       BEFORE UPDATE ON isc_sam_action        FOR EACH ROW EXECUTE FUNCTION touch_record_updated_date();
CREATE TRIGGER trg_touch_sam_menu         BEFORE UPDATE ON isc_sam_menu          FOR EACH ROW EXECUTE FUNCTION touch_record_updated_date();
CREATE TRIGGER trg_touch_sam_menu_action  BEFORE UPDATE ON isc_sam_menu_action   FOR EACH ROW EXECUTE FUNCTION touch_record_updated_date();
CREATE TRIGGER trg_touch_sam_menu_link    BEFORE UPDATE ON isc_sam_menu_link     FOR EACH ROW EXECUTE FUNCTION touch_record_updated_date();
CREATE TRIGGER trg_touch_sam_role         BEFORE UPDATE ON isc_sam_role          FOR EACH ROW EXECUTE FUNCTION touch_record_updated_date();
CREATE TRIGGER trg_touch_sam_accesscontrol BEFORE UPDATE ON isc_sam_accesscontrol FOR EACH ROW EXECUTE FUNCTION touch_record_updated_date();
CREATE TRIGGER trg_touch_sam_team         BEFORE UPDATE ON isc_sam_team          FOR EACH ROW EXECUTE FUNCTION touch_record_updated_date();
CREATE TRIGGER trg_touch_sam_team_role    BEFORE UPDATE ON isc_sam_team_role     FOR EACH ROW EXECUTE FUNCTION touch_record_updated_date();
CREATE TRIGGER trg_touch_sam_staff        BEFORE UPDATE ON isc_sam_staff         FOR EACH ROW EXECUTE FUNCTION touch_record_updated_date();
CREATE TRIGGER trg_touch_sam_staff_branch BEFORE UPDATE ON isc_sam_staff_branch  FOR EACH ROW EXECUTE FUNCTION touch_record_updated_date();

-- ---------------------------------------------------------------------
-- 13. Wire hsm_command_audit to staff (replace VARCHAR user_id)
-- ---------------------------------------------------------------------
ALTER TABLE hsm_command_audit
    ADD COLUMN sam_staff_id BIGINT REFERENCES isc_sam_staff(rec_id) ON DELETE RESTRICT,
    ADD COLUMN sam_team_id  BIGINT REFERENCES isc_sam_team(rec_id)  ON DELETE RESTRICT,
    ADD COLUMN sam_role_id  BIGINT REFERENCES isc_sam_role(rec_id)  ON DELETE RESTRICT;
CREATE INDEX ix_audit_staff ON hsm_command_audit(sam_staff_id);

-- ---------------------------------------------------------------------
-- 14. Seed: actions, menus, roles for ISC house bank
-- ---------------------------------------------------------------------
INSERT INTO isc_sam_action (name, description) VALUES
    ('KEY_CREATE_RSA',  'Generate RSA keypair (EI/EJ)'),
    ('KEY_CREATE_SYM',  'Generate symmetric key (A0/A1)'),
    ('KEY_IMPORT',      'Import wrapped key (GI/GJ)'),
    ('KEY_EXPORT',      'Export key under KBPK/ZMK (A8/A9)'),
    ('KEY_READ',        'List/view keys'),
    ('KEY_DELETE',      'Revoke/delete key'),
    ('CRYPTO_ENCRYPT',  'Data encryption (M0/M1)'),
    ('CRYPTO_DECRYPT',  'Data decryption (M2/M3)'),
    ('MAC_GEN',         'MAC generation'),
    ('MAC_VRFY',        'MAC verification'),
    ('PIN_VRFY',        'PIN verification'),
    ('PIN_XLATE',       'PIN translation'),
    ('ADMIN_POOL',      'Manage HSM pools/nodes'),
    ('ADMIN_AUDIT',     'Read audit trail'),
    ('ADMIN_RBAC',      'Manage SAM roles/staff'),
    ('RAW_CMD',         'Send raw HSM command (passthrough)');

-- Menus under ISC house bank
INSERT INTO isc_sam_menu (ms_bank_id, menu_name, display_name, url, sort_order)
SELECT b.rec_id, m.menu_name, m.display_name, m.url, m.sort_order
FROM isc_ms_bank b,
     (VALUES
        ('KEY_MGMT',  'Key Management', '/keys',         10),
        ('GEN_RSA',   'Generate RSA',   '/keys/new',     20),
        ('IMPORT',    'Import Key',     '/keys/import',  30),
        ('EXPORT',    'Export Key',     '/keys/export',  40),
        ('DECRYPT',   'Decrypt',        '/crypto',       50),
        ('POOLS',     'HSM Pools',      '/pools',        60),
        ('AUDIT',     'Audit Trail',    '/audit',        70),
        ('RBAC',      'RBAC Admin',     '/admin/rbac',   80),
        ('RAW',       'Raw Console',    '/console',      90)
     ) m(menu_name, display_name, url, sort_order)
WHERE b.code = 'ISC';

-- Default roles for ISC house bank
INSERT INTO isc_sam_role (ms_bank_id, role_name, description)
SELECT b.rec_id, r.role_name, r.description
FROM isc_ms_bank b,
     (VALUES
        ('ADMIN',       'Full access'),
        ('KEY_MANAGER', 'Create/import/export keys'),
        ('CRYPTO_USER', 'Encrypt/decrypt/MAC ops'),
        ('AUDITOR',     'Read-only audit access')
     ) r(role_name, description)
WHERE b.code = 'ISC';

-- ADMIN role: grant every (menu, action) — full access matrix
INSERT INTO isc_sam_accesscontrol (sam_role_id, sam_menu_id, sam_action_id)
SELECT r.rec_id, m.rec_id, a.rec_id
FROM isc_sam_role   r
JOIN isc_ms_bank    b ON b.rec_id = r.ms_bank_id AND b.code = 'ISC'
JOIN isc_sam_menu   m ON m.ms_bank_id = b.rec_id
JOIN isc_sam_action a ON TRUE
WHERE r.role_name = 'ADMIN';

-- House team + admin staff
INSERT INTO isc_sam_team (ms_bank_id, team_code, team_name)
SELECT rec_id, 'ADMIN', 'Administrators' FROM isc_ms_bank WHERE code = 'ISC';

INSERT INTO isc_sam_team_role (sam_team_id, sam_role_id)
SELECT t.rec_id, r.rec_id
FROM isc_sam_team t
JOIN isc_sam_role r ON r.ms_bank_id = t.ms_bank_id AND r.role_name = 'ADMIN'
WHERE t.team_code = 'ADMIN';

-- Bootstrap admin staff (login: admin / password set by app on first login — force_change_pwd_flag = Y)
INSERT INTO isc_sam_staff
    (staff_fname, staff_lname, staff_email,
     ms_bank_id, sam_team_id,
     staff_loginname, user_status_code, force_change_pwd_flag)
SELECT 'System', 'Administrator', 'admin@isc.local',
       b.rec_id, t.rec_id,
       'admin', 'ACTIVE', 'Y'
FROM isc_ms_bank b
JOIN isc_sam_team t ON t.ms_bank_id = b.rec_id AND t.team_code = 'ADMIN'
WHERE b.code = 'ISC';
