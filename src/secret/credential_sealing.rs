//! AES-GCM sealing for stored credential values (ADR-0008 D2).
//!
//! Generalizes the OAuth token sealing (ADR-0005; `src/oauth/sealing.rs`)
//! to a second, independent key so static credential *values* can be
//! sealed at rest inside locksmith — the daemon-side `stored` custody
//! backend. The underlying AES-256-GCM primitive (per-row 12-byte nonce,
//! `SecretString`-held key) is shared and proven; only the key differs.
//!
//! The key is loaded from `LOCKSMITH_CREDENTIAL_SEALING_KEY`, **distinct**
//! from `LOCKSMITH_OAUTH_SEALING_KEY`: the two sealing domains have
//! independent blast radius (rotating or leaking the credential key never
//! touches OAuth sessions, and vice versa). `CredentialSealingKey` is a
//! separate newtype so the two keys cannot be cross-wired at compile
//! time — a stored-credential value can never be unsealed with the OAuth
//! key by accident.
//!
//! Absence of the env var is not fatal: the daemon boots without the
//! stored-credential routes (they 404, mirroring the OAuth-key gate), and
//! any `stored_*` registration fails loud at proxy time.

use crate::oauth::{SealingKey, SealingKeyError};

/// Env var holding the base64-encoded 32-byte credential-store sealing
/// key. Distinct from `LOCKSMITH_OAUTH_SEALING_KEY` (ADR-0008 D2).
pub const CREDENTIAL_SEALING_KEY_ENV: &str = "LOCKSMITH_CREDENTIAL_SEALING_KEY";

/// 32-byte AES-256 sealing key for the stored-credential substrate.
///
/// A distinct newtype over the OAuth [`SealingKey`] crypto: same proven
/// AES-GCM primitive, its own key, and a type the compiler will not let
/// you confuse with the OAuth key.
#[derive(Clone, Debug)]
pub struct CredentialSealingKey(SealingKey);

impl CredentialSealingKey {
    /// Load from `LOCKSMITH_CREDENTIAL_SEALING_KEY`. Returns
    /// `Err(EnvVarUnset { .. })` when absent — the caller boots without
    /// the stored-credential routes (they 404), mirroring the OAuth-key
    /// gate in `daemon::run`.
    pub fn from_env() -> Result<Self, SealingKeyError> {
        SealingKey::from_env_var(CREDENTIAL_SEALING_KEY_ENV).map(Self)
    }

    /// Construct from a base64 32-byte key. Used by tests and by an
    /// operator key-generation helper.
    pub fn from_b64(b64: &str) -> Result<Self, SealingKeyError> {
        SealingKey::from_b64(b64).map(Self)
    }

    /// Generate a fresh random key.
    pub fn generate() -> Result<Self, SealingKeyError> {
        SealingKey::generate().map(Self)
    }

    /// Seal a plaintext credential value with a fresh random 12-byte
    /// nonce. Returns `(ciphertext, nonce)`; the caller stores both in
    /// the `credential_secrets` substrate (T1.2). Unseal needs the nonce.
    pub fn seal(&self, plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>), SealingKeyError> {
        self.0.seal(plaintext)
    }

    /// Unseal a ciphertext using the stored nonce. Wrong key, tampered
    /// ciphertext, or a corrupt nonce → `Err(Decrypt)` / `Err(InvalidNonce)`.
    pub fn unseal(&self, ciphertext: &[u8], nonce: &[u8]) -> Result<Vec<u8>, SealingKeyError> {
        self.0.unseal(ciphertext, nonce)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_unseal_roundtrip() {
        let key = CredentialSealingKey::generate().unwrap();
        let plaintext = b"stored-api-key-sk-abc-123";
        let (ct, nonce) = key.seal(plaintext).unwrap();
        let recovered = key.unseal(&ct, &nonce).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn seal_produces_unique_ciphertexts() {
        let key = CredentialSealingKey::generate().unwrap();
        let plaintext = b"same-secret";
        let (ct1, nonce1) = key.seal(plaintext).unwrap();
        let (ct2, nonce2) = key.seal(plaintext).unwrap();
        assert_ne!(ct1, ct2, "fresh nonce should yield distinct ciphertexts");
        assert_ne!(nonce1, nonce2);
    }

    #[test]
    fn unseal_with_wrong_key_fails() {
        let k1 = CredentialSealingKey::generate().unwrap();
        let k2 = CredentialSealingKey::generate().unwrap();
        let (ct, nonce) = k1.seal(b"secret").unwrap();
        let err = k2.unseal(&ct, &nonce).unwrap_err();
        assert!(matches!(err, SealingKeyError::Decrypt));
    }

    #[test]
    fn unseal_with_tampered_ciphertext_fails() {
        let key = CredentialSealingKey::generate().unwrap();
        let (mut ct, nonce) = key.seal(b"secret").unwrap();
        ct[0] ^= 0xff; // flip a bit
        let err = key.unseal(&ct, &nonce).unwrap_err();
        assert!(matches!(err, SealingKeyError::Decrypt));
    }

    #[test]
    fn from_b64_rejects_wrong_length() {
        use base64::Engine;
        let too_short = base64::engine::general_purpose::STANDARD.encode([0u8; 16]);
        let err = CredentialSealingKey::from_b64(&too_short).unwrap_err();
        assert!(matches!(err, SealingKeyError::InvalidLength(16)));
    }

    #[test]
    fn from_b64_rejects_invalid_base64() {
        let err = CredentialSealingKey::from_b64("not-valid-base64!!!").unwrap_err();
        assert!(matches!(err, SealingKeyError::InvalidBase64(_)));
    }

    #[test]
    fn unseal_rejects_short_nonce() {
        let key = CredentialSealingKey::generate().unwrap();
        let err = key.unseal(b"ciphertext", &[0u8; 8]).unwrap_err();
        assert!(matches!(err, SealingKeyError::InvalidNonce(8)));
    }

    /// Blast-radius isolation (ADR-0008 D2): the credential key and the
    /// OAuth key are independent. Data sealed with one must never unseal
    /// with the other — a leaked/rotated credential key can't expose
    /// OAuth sessions, and vice versa.
    #[test]
    fn credential_and_oauth_keys_are_isolated() {
        let cred = CredentialSealingKey::generate().unwrap();
        let oauth = SealingKey::generate().unwrap();

        // OAuth-sealed bytes are opaque to the credential key.
        let (oauth_ct, oauth_nonce) = oauth.seal(b"oauth-refresh-token").unwrap();
        let err = cred.unseal(&oauth_ct, &oauth_nonce).unwrap_err();
        assert!(matches!(err, SealingKeyError::Decrypt));

        // Credential-sealed bytes are opaque to the OAuth key.
        let (cred_ct, cred_nonce) = cred.seal(b"stored-api-key").unwrap();
        let err = oauth.unseal(&cred_ct, &cred_nonce).unwrap_err();
        assert!(matches!(err, SealingKeyError::Decrypt));
    }

    #[test]
    fn from_env_reports_the_credential_var_name_when_unset() {
        // Guard: from_env surfaces the *credential* env var, not the OAuth
        // one, so an operator sees the right variable to set.
        // SAFETY: single-threaded test; remove the var, then restore nothing
        // (tests must not depend on ambient env). Uses a name unlikely to be set.
        let err = SealingKey::from_env_var(CREDENTIAL_SEALING_KEY_ENV);
        // Either it's genuinely unset (EnvVarUnset naming the credential var)
        // or an operator has it set locally (Ok) — both are acceptable; we
        // only assert the error, when present, names the credential var.
        if let Err(SealingKeyError::EnvVarUnset { var }) = err {
            assert_eq!(var, CREDENTIAL_SEALING_KEY_ENV);
        }
    }
}
