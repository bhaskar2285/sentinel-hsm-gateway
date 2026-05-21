-- V4 — Mark hsm_key rows with no LMK material as INVALID.
--
-- Some keys were persisted before the create-path guards landed
-- (rsa2 / imp-key / final-rsa style). They have NULL or zero-length
-- encrypted_blob and cause "VL: Source key has no LMK-encrypted
-- material" on any export attempt. Mark them so the UI hides them
-- and the export endpoint rejects with a clearer message.
--
-- Audit trail is preserved (record_status untouched).

UPDATE hsm_key
   SET status = 'INVALID'
 WHERE status <> 'INVALID'
   AND (encrypted_blob IS NULL OR octet_length(encrypted_blob) = 0);
