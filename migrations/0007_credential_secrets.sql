-- Phase J / T1.2 (CCS-1, CCS-6): sealed stored-credential substrate.
--
-- Holds AES-GCM-sealed credential VALUES for the `stored` custody
-- backend (agents-stack ADR-0008). The `stored_*` AuthSpec variants
-- carry only the opaque `secret_ref` handle; the ciphertext and its
-- per-row 12-byte nonce live here, sealed with the independent
-- LOCKSMITH_CREDENTIAL_SEALING_KEY (secret::CredentialSealingKey, T1.1) —
-- a separate key from the OAuth sealing key, so the two secret domains
-- have independent blast radius.
--
-- Reveal-never: there is no plaintext column, ever. Reads return the
-- sealed bytes + set_at only. Rotation inserts a fresh row (new
-- secret_ref) and tombstones the old one — plaintext is never mutated in
-- place and never re-fetchable. The retention sweep hard-deletes
-- tombstoned rows past a grace cutoff.

CREATE TABLE IF NOT EXISTS credential_secrets (
    secret_ref    TEXT    PRIMARY KEY,
    sealed_value  BLOB    NOT NULL,
    nonce         BLOB    NOT NULL,
    set_at        INTEGER NOT NULL,
    tombstoned_at INTEGER
);

-- Supports the retention sweep over tombstoned rows.
CREATE INDEX IF NOT EXISTS idx_credential_secrets_tombstoned
    ON credential_secrets (tombstoned_at);
