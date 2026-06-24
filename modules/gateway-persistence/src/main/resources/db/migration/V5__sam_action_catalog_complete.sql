-- =====================================================================
-- sentinel-hsm-gateway schema V5
-- Complete the SAM action catalog so every controller @PreAuthorize("OP_*")
-- has a backing isc_sam_action row, then re-grant the full (menu × action)
-- matrix to every ADMIN role. Additive only — V3 is immutable (already applied).
--
-- Without this, the secured (non-dev) profile rejects most commands with 403
-- even for ADMIN, because V3 seeded only a partial action set.
-- =====================================================================

INSERT INTO isc_sam_action (name, description) VALUES
    ('KEY_CREATE_SYM',     'Generate symmetric key (A0)'),
    ('KEY_IMPORT_ZMK',     'Import key under ZMK (A6/A8)'),
    ('KEY_CHECK_VALUE',    'Generate key check value (BU)'),
    ('KEY_COMPONENT_GEN',  'Generate key component (GG)'),
    ('KEY_FORM_COMPONENTS','Form key from components (GK/A4)'),
    ('KEY_FORM_BLOCK',     'Form TR-31/X9.143 key block (B4)'),
    ('CVV_GEN',            'Generate CVV/CVC (CW)'),
    ('CVV_VERIFY',         'Verify CVV/CVC (CY)'),
    ('DCVV_VERIFY',        'Verify dynamic CVV (dCVV)'),
    ('CSC_CALC',           'Calculate card security code'),
    ('CSC_VERIFY',         'Verify card security code'),
    ('ARQC_VERIFY',        'Verify ARQC / EMV cryptogram'),
    ('PIN_GEN',            'Generate PIN'),
    ('PIN_VERIFY',         'Verify PIN'),
    ('PIN_TRANSLATE',      'Translate PIN block'),
    ('PVV_GEN',            'Generate Visa PVV'),
    ('IBM_OFFSET_GEN',     'Generate IBM PIN offset'),
    ('HMAC_GEN',           'Generate HMAC (LQ)'),
    ('HMAC_VERIFY',        'Verify HMAC (LS)'),
    ('HSM_STATUS',         'HSM status / diagnostics'),
    ('HSM_ECHO',           'HSM echo'),
    ('ADMIN_POOL',         'Manage HSM pools/nodes')
ON CONFLICT (name) DO NOTHING;

-- Re-grant the complete (menu × action) matrix to every ADMIN role across banks.
-- uk_sam_access (sam_role_id, sam_menu_id, sam_action_id) makes this idempotent.
INSERT INTO isc_sam_accesscontrol (sam_role_id, sam_menu_id, sam_action_id)
SELECT r.rec_id, m.rec_id, a.rec_id
FROM isc_sam_role   r
JOIN isc_sam_menu   m ON m.ms_bank_id = r.ms_bank_id
JOIN isc_sam_action a ON TRUE
WHERE r.role_name = 'ADMIN'
ON CONFLICT ON CONSTRAINT uk_sam_access DO NOTHING;
