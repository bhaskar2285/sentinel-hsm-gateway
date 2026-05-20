-- =====================================================================
-- sentinel-hsm-gateway schema V2
-- Adopts ISC standard schema conventions seen in xenticate-liquibase:
--   * isc_ms_bank   (FI master with fiid)
--   * isc_ms_branch (branch master, extension of ISC pattern)
--   * 15-column ISC audit template on every business table:
--       record_status,
--       record_created_date/id/name/team_code/team_name/bank_code/bank_name,
--       record_updated_date/id/name/team_code/team_name/bank_code/bank_name
--   * fi_id + branch_id lineage on hsm_pool, hsm_key, hsm_command_audit
-- =====================================================================

-- ---------------------------------------------------------------------
-- 1. isc_ms_bank — Financial Institution master (FIID)
-- ---------------------------------------------------------------------
CREATE TABLE isc_ms_bank (
    rec_id                      BIGSERIAL    PRIMARY KEY,
    code                        VARCHAR(20)  NOT NULL UNIQUE,
    name                        VARCHAR(50)  NOT NULL,
    description                 VARCHAR(100),
    short_code                  VARCHAR(6),
    fiid                        VARCHAR(10),
    is_default                  CHAR(1)      NOT NULL DEFAULT 'N',
    login_method_type           VARCHAR(10)  NOT NULL DEFAULT 'DB',          -- DB | LDAP | MSAD | OIDC
    ldap_ip                     VARCHAR(20),
    ldap_port                   INTEGER,
    base_dn                     VARCHAR(100),
    search_base_dn              VARCHAR(50),
    permission_method_type      VARCHAR(10)  NOT NULL DEFAULT 'DB',          -- DB | LDAP | IDM
    idm_ip                      VARCHAR(20),
    idm_port                    INTEGER,
    country_iso2                CHAR(2),
    swift_bic                   VARCHAR(11),
    regulator_id                VARCHAR(64),
    -- ISC audit template (15 cols)
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
CREATE INDEX ix_isc_ms_bank_status ON isc_ms_bank(record_status);
CREATE INDEX ix_isc_ms_bank_fiid   ON isc_ms_bank(fiid);

-- ---------------------------------------------------------------------
-- 2. isc_ms_branch — Branch master (ISC pattern extended)
-- ---------------------------------------------------------------------
CREATE TABLE isc_ms_branch (
    rec_id                      BIGSERIAL    PRIMARY KEY,
    bank_rec_id                 BIGINT       NOT NULL REFERENCES isc_ms_bank(rec_id) ON DELETE RESTRICT,
    code                        VARCHAR(20)  NOT NULL,                       -- branch code (IFSC/SWIFT branch/ABA)
    name                        VARCHAR(50)  NOT NULL,
    description                 VARCHAR(100),
    short_code                  VARCHAR(6),
    city                        VARCHAR(50),
    region                      VARCHAR(50),
    country_iso2                CHAR(2),
    -- ISC audit template
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
    CONSTRAINT uk_branch_code UNIQUE (bank_rec_id, code)
);
CREATE INDEX ix_isc_ms_branch_bank   ON isc_ms_branch(bank_rec_id);
CREATE INDEX ix_isc_ms_branch_status ON isc_ms_branch(record_status);

-- ---------------------------------------------------------------------
-- 3. Apply ISC template + FI/branch FKs to existing business tables
--    DEFAULT clauses backfill V1 rows during ALTER.
-- ---------------------------------------------------------------------

-- ---- hsm_pool ----
ALTER TABLE hsm_pool
    ADD COLUMN bank_rec_id                 BIGINT       REFERENCES isc_ms_bank(rec_id)   ON DELETE RESTRICT,
    ADD COLUMN record_status               CHAR(1)      NOT NULL DEFAULT 'Y',
    ADD COLUMN record_created_date         TIMESTAMP    NOT NULL DEFAULT NOW(),
    ADD COLUMN record_created_id           INTEGER      NOT NULL DEFAULT 0,
    ADD COLUMN record_created_name         VARCHAR(50)  NOT NULL DEFAULT 'SYSTEM',
    ADD COLUMN record_created_team_code    VARCHAR(20)  NOT NULL DEFAULT 'SYSTEM',
    ADD COLUMN record_created_team_name    VARCHAR(50)  NOT NULL DEFAULT 'SYSTEM',
    ADD COLUMN record_created_bank_code    VARCHAR(20)  NOT NULL DEFAULT 'ISC',
    ADD COLUMN record_created_bank_name    VARCHAR(50)  NOT NULL DEFAULT 'ISC',
    ADD COLUMN record_updated_date         TIMESTAMP    NOT NULL DEFAULT NOW(),
    ADD COLUMN record_updated_id           INTEGER      NOT NULL DEFAULT 0,
    ADD COLUMN record_updated_name         VARCHAR(50)  NOT NULL DEFAULT 'SYSTEM',
    ADD COLUMN record_updated_team_code    VARCHAR(20)  NOT NULL DEFAULT 'SYSTEM',
    ADD COLUMN record_updated_team_name    VARCHAR(50)  NOT NULL DEFAULT 'SYSTEM',
    ADD COLUMN record_updated_bank_code    VARCHAR(20)  NOT NULL DEFAULT 'ISC',
    ADD COLUMN record_updated_bank_name    VARCHAR(50)  NOT NULL DEFAULT 'ISC';
CREATE INDEX ix_hsm_pool_bank ON hsm_pool(bank_rec_id);

-- ---- hsm_node ----
ALTER TABLE hsm_node
    ADD COLUMN record_status               CHAR(1)      NOT NULL DEFAULT 'Y',
    ADD COLUMN record_created_date         TIMESTAMP    NOT NULL DEFAULT NOW(),
    ADD COLUMN record_created_id           INTEGER      NOT NULL DEFAULT 0,
    ADD COLUMN record_created_name         VARCHAR(50)  NOT NULL DEFAULT 'SYSTEM',
    ADD COLUMN record_created_team_code    VARCHAR(20)  NOT NULL DEFAULT 'SYSTEM',
    ADD COLUMN record_created_team_name    VARCHAR(50)  NOT NULL DEFAULT 'SYSTEM',
    ADD COLUMN record_created_bank_code    VARCHAR(20)  NOT NULL DEFAULT 'ISC',
    ADD COLUMN record_created_bank_name    VARCHAR(50)  NOT NULL DEFAULT 'ISC',
    ADD COLUMN record_updated_date         TIMESTAMP    NOT NULL DEFAULT NOW(),
    ADD COLUMN record_updated_id           INTEGER      NOT NULL DEFAULT 0,
    ADD COLUMN record_updated_name         VARCHAR(50)  NOT NULL DEFAULT 'SYSTEM',
    ADD COLUMN record_updated_team_code    VARCHAR(20)  NOT NULL DEFAULT 'SYSTEM',
    ADD COLUMN record_updated_team_name    VARCHAR(50)  NOT NULL DEFAULT 'SYSTEM',
    ADD COLUMN record_updated_bank_code    VARCHAR(20)  NOT NULL DEFAULT 'ISC',
    ADD COLUMN record_updated_bank_name    VARCHAR(50)  NOT NULL DEFAULT 'ISC';

-- ---- hsm_key ----
ALTER TABLE hsm_key
    ADD COLUMN bank_rec_id                 BIGINT       REFERENCES isc_ms_bank(rec_id)   ON DELETE RESTRICT,
    ADD COLUMN branch_rec_id               BIGINT       REFERENCES isc_ms_branch(rec_id) ON DELETE RESTRICT,
    ADD COLUMN purpose                     VARCHAR(64),                         -- ATM_PIN, POS_MAC, ISS_3DS, ECOM_TOKEN, INTERCHANGE_ZMK
    ADD COLUMN record_status               CHAR(1)      NOT NULL DEFAULT 'Y',
    ADD COLUMN record_created_date         TIMESTAMP    NOT NULL DEFAULT NOW(),
    ADD COLUMN record_created_id           INTEGER      NOT NULL DEFAULT 0,
    ADD COLUMN record_created_name         VARCHAR(50)  NOT NULL DEFAULT 'SYSTEM',
    ADD COLUMN record_created_team_code    VARCHAR(20)  NOT NULL DEFAULT 'SYSTEM',
    ADD COLUMN record_created_team_name    VARCHAR(50)  NOT NULL DEFAULT 'SYSTEM',
    ADD COLUMN record_created_bank_code    VARCHAR(20)  NOT NULL DEFAULT 'ISC',
    ADD COLUMN record_created_bank_name    VARCHAR(50)  NOT NULL DEFAULT 'ISC',
    ADD COLUMN record_updated_date         TIMESTAMP    NOT NULL DEFAULT NOW(),
    ADD COLUMN record_updated_id           INTEGER      NOT NULL DEFAULT 0,
    ADD COLUMN record_updated_name         VARCHAR(50)  NOT NULL DEFAULT 'SYSTEM',
    ADD COLUMN record_updated_team_code    VARCHAR(20)  NOT NULL DEFAULT 'SYSTEM',
    ADD COLUMN record_updated_team_name    VARCHAR(50)  NOT NULL DEFAULT 'SYSTEM',
    ADD COLUMN record_updated_bank_code    VARCHAR(20)  NOT NULL DEFAULT 'ISC',
    ADD COLUMN record_updated_bank_name    VARCHAR(50)  NOT NULL DEFAULT 'ISC';
CREATE INDEX ix_hsm_key_bank    ON hsm_key(bank_rec_id);
CREATE INDEX ix_hsm_key_branch  ON hsm_key(branch_rec_id);
CREATE INDEX ix_hsm_key_purpose ON hsm_key(purpose);
CREATE INDEX ix_hsm_key_recstat ON hsm_key(record_status);

-- ---- hsm_key_block ----
ALTER TABLE hsm_key_block
    ADD COLUMN record_status               CHAR(1)      NOT NULL DEFAULT 'Y',
    ADD COLUMN record_created_date         TIMESTAMP    NOT NULL DEFAULT NOW(),
    ADD COLUMN record_created_id           INTEGER      NOT NULL DEFAULT 0,
    ADD COLUMN record_created_name         VARCHAR(50)  NOT NULL DEFAULT 'SYSTEM',
    ADD COLUMN record_created_team_code    VARCHAR(20)  NOT NULL DEFAULT 'SYSTEM',
    ADD COLUMN record_created_team_name    VARCHAR(50)  NOT NULL DEFAULT 'SYSTEM',
    ADD COLUMN record_created_bank_code    VARCHAR(20)  NOT NULL DEFAULT 'ISC',
    ADD COLUMN record_created_bank_name    VARCHAR(50)  NOT NULL DEFAULT 'ISC',
    ADD COLUMN record_updated_date         TIMESTAMP    NOT NULL DEFAULT NOW(),
    ADD COLUMN record_updated_id           INTEGER      NOT NULL DEFAULT 0,
    ADD COLUMN record_updated_name         VARCHAR(50)  NOT NULL DEFAULT 'SYSTEM',
    ADD COLUMN record_updated_team_code    VARCHAR(20)  NOT NULL DEFAULT 'SYSTEM',
    ADD COLUMN record_updated_team_name    VARCHAR(50)  NOT NULL DEFAULT 'SYSTEM',
    ADD COLUMN record_updated_bank_code    VARCHAR(20)  NOT NULL DEFAULT 'ISC',
    ADD COLUMN record_updated_bank_name    VARCHAR(50)  NOT NULL DEFAULT 'ISC';

-- ---- hsm_command_audit: append-only forensic table.
--      ISC "record_*" not applicable (never updated), but FI/branch lineage required.
ALTER TABLE hsm_command_audit
    ADD COLUMN bank_rec_id   BIGINT REFERENCES isc_ms_bank(rec_id)   ON DELETE RESTRICT,
    ADD COLUMN branch_rec_id BIGINT REFERENCES isc_ms_branch(rec_id) ON DELETE RESTRICT,
    ADD COLUMN fiid          VARCHAR(10),                            -- denormalized for regulator queries
    ADD COLUMN user_team_code VARCHAR(20),
    ADD COLUMN user_team_name VARCHAR(50),
    ADD COLUMN user_bank_code VARCHAR(20),
    ADD COLUMN user_bank_name VARCHAR(50);
CREATE INDEX ix_audit_bank   ON hsm_command_audit(bank_rec_id);
CREATE INDEX ix_audit_branch ON hsm_command_audit(branch_rec_id);
CREATE INDEX ix_audit_fiid   ON hsm_command_audit(fiid);

-- ---- RBAC scope binding ----
ALTER TABLE rbac_user_role
    ADD COLUMN bank_rec_id   BIGINT REFERENCES isc_ms_bank(rec_id)   ON DELETE CASCADE,
    ADD COLUMN branch_rec_id BIGINT REFERENCES isc_ms_branch(rec_id) ON DELETE CASCADE;

-- ---------------------------------------------------------------------
-- 4. updated_* auto-touch trigger
--    Application supplies record_updated_id/name/team/bank; trigger maintains date.
-- ---------------------------------------------------------------------
CREATE OR REPLACE FUNCTION touch_record_updated_date() RETURNS TRIGGER AS $$
BEGIN
    NEW.record_updated_date := NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_touch_bank        BEFORE UPDATE ON isc_ms_bank   FOR EACH ROW EXECUTE FUNCTION touch_record_updated_date();
CREATE TRIGGER trg_touch_branch      BEFORE UPDATE ON isc_ms_branch FOR EACH ROW EXECUTE FUNCTION touch_record_updated_date();
CREATE TRIGGER trg_touch_pool        BEFORE UPDATE ON hsm_pool      FOR EACH ROW EXECUTE FUNCTION touch_record_updated_date();
CREATE TRIGGER trg_touch_node        BEFORE UPDATE ON hsm_node      FOR EACH ROW EXECUTE FUNCTION touch_record_updated_date();
CREATE TRIGGER trg_touch_key         BEFORE UPDATE ON hsm_key       FOR EACH ROW EXECUTE FUNCTION touch_record_updated_date();
CREATE TRIGGER trg_touch_key_block   BEFORE UPDATE ON hsm_key_block FOR EACH ROW EXECUTE FUNCTION touch_record_updated_date();

-- ---------------------------------------------------------------------
-- 5. Seed: ISC house bank (matches Thailand precedent)
-- ---------------------------------------------------------------------
INSERT INTO isc_ms_bank
    (code, name, description, short_code, fiid, is_default,
     login_method_type, permission_method_type, country_iso2)
VALUES
    ('ISC',      'ISC House Tenant',     'Internal Sentinel Tenant', 'ISC',  '0000000000', 'Y', 'DB', 'DB', 'IN'),
    ('SENTINEL', 'Sentinel Demo Bank',   'Demo / development bank',  'SNT',  '9999999999', 'N', 'DB', 'DB', 'IN');

-- Backfill V1 hsm_key + hsm_pool rows to ISC house bank
UPDATE hsm_key
   SET bank_rec_id = (SELECT rec_id FROM isc_ms_bank WHERE code = 'ISC')
 WHERE bank_rec_id IS NULL;

UPDATE hsm_pool
   SET bank_rec_id = (SELECT rec_id FROM isc_ms_bank WHERE code = 'ISC')
 WHERE bank_rec_id IS NULL;
