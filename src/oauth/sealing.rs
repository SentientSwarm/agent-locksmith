//! AES-GCM sealing for OAuth refresh + access tokens. ADR-0005 D2.
//!
//! Sealing key bootstrap: read from `LOCKSMITH_OAUTH_SEALING_KEY` env
//! var at daemon startup. Expected: base64-encoded 32 bytes (AES-256
//! key size). Operator generates with
//! `openssl rand -base64 32 | tee >(your-seal-mechanism)`.
//!
//! Per-row 12-byte AES-GCM nonce. Tampering with ciphertext fails the
//! GCM tag check, surfaces as `SealingKeyError::Decrypt`.
//!
//! The sealing key is held in `SecretString` (zeroized on drop) and
//! only re-materialized into the AES-GCM cipher inside `seal()` /
//! `unseal()`. The cipher itself isn't `Send + Sync`-safe to keep
//! around long-term; we rebuild it per call.

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use secrecy::{ExposeSecret, SecretString};

const SEALING_KEY_ENV: &str = "LOCKSMITH_OAUTH_SEALING_KEY";
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;

/// Errors that can occur during sealing-key bootstrap or seal/unseal
/// operations.
#[derive(Debug, thiserror::Error)]
pub enum SealingKeyError {
    /// `LOCKSMITH_OAUTH_SEALING_KEY` env var is absent or empty.
    /// Without it the OAuth session table cannot be sealed; daemon
    /// configures itself with `oauth = None` and OAuth registrations
    /// fail at proxy time with a clear `oauth_sealing_key_unset`
    /// envelope code (Phase F.5 surfaces this).
    #[error("LOCKSMITH_OAUTH_SEALING_KEY env var not set or empty")]
    EnvVarUnset,

    /// Env var is set but doesn't decode as base64.
    #[error("LOCKSMITH_OAUTH_SEALING_KEY is not valid base64: {0}")]
    InvalidBase64(String),

    /// Decoded length isn't exactly 32 bytes.
    #[error("LOCKSMITH_OAUTH_SEALING_KEY must decode to 32 bytes, got {0}")]
    InvalidLength(usize),

    /// Nonce bytes weren't exactly 12 bytes during unseal.
    #[error("OAuth ciphertext nonce must be 12 bytes, got {0}")]
    InvalidNonce(usize),

    /// AES-GCM rejected the ciphertext. Likely cause: wrong sealing key
    /// (operator rotated it without re-bootstrapping), tampering, or
    /// corruption. The proxy hot path treats this as a degraded
    /// session.
    #[error("OAuth ciphertext failed authentication (wrong key or tampered)")]
    Decrypt,

    /// Random nonce generation failed at the OS level. Extremely
    /// unlikely; bubbles up as a 5xx.
    #[error("failed to generate AES-GCM nonce: {0}")]
    NonceGenFailed(String),
}

/// 32-byte AES-256 key, held in a `SecretString` so it gets zeroized
/// on drop and stays out of debug logs.
#[derive(Clone)]
pub struct SealingKey {
    key: SecretString,
}

impl std::fmt::Debug for SealingKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never debug-print the key.
        f.write_str("SealingKey(<redacted>)")
    }
}

impl SealingKey {
    /// Load from the `LOCKSMITH_OAUTH_SEALING_KEY` env var. Returns
    /// `Err(EnvVarUnset)` when absent — caller decides whether that's
    /// fatal (OAuth registrations present in catalog → fatal) or
    /// acceptable (no OAuth registrations → boot without OAuth
    /// sealing).
    pub fn from_env() -> Result<Self, SealingKeyError> {
        let raw = std::env::var(SEALING_KEY_ENV).map_err(|_| SealingKeyError::EnvVarUnset)?;
        if raw.is_empty() {
            return Err(SealingKeyError::EnvVarUnset);
        }
        Self::from_b64(&raw)
    }

    /// Construct from a base64 string. Used by `from_env()` and by
    /// tests that supply a known key.
    pub fn from_b64(b64: &str) -> Result<Self, SealingKeyError> {
        let bytes = B64
            .decode(b64.trim())
            .map_err(|e| SealingKeyError::InvalidBase64(e.to_string()))?;
        if bytes.len() != KEY_LEN {
            return Err(SealingKeyError::InvalidLength(bytes.len()));
        }
        // SecretString holds owned String; convert bytes via base64.
        Ok(Self {
            key: SecretString::from(B64.encode(bytes)),
        })
    }

    /// Generate a fresh random key. Used by tests and by an operator
    /// helper (Phase F.4 may expose `locksmith oauth gen-sealing-key`).
    pub fn generate() -> Result<Self, SealingKeyError> {
        let mut bytes = [0u8; KEY_LEN];
        getrandom::fill(&mut bytes).map_err(|e| SealingKeyError::NonceGenFailed(e.to_string()))?;
        Ok(Self {
            key: SecretString::from(B64.encode(bytes)),
        })
    }

    fn cipher(&self) -> Result<Aes256Gcm, SealingKeyError> {
        let bytes = B64
            .decode(self.key.expose_secret())
            .map_err(|e| SealingKeyError::InvalidBase64(e.to_string()))?;
        // Aes256Gcm::new takes a Key (a fixed-size array reference).
        Ok(Aes256Gcm::new_from_slice(&bytes).expect("32-byte key constructed; new_from_slice ok"))
    }

    /// Seal a plaintext byte slice with a fresh random 12-byte nonce.
    /// Returns `(ciphertext, nonce)`. The caller stores both in the
    /// `oauth_sessions` table; unseal needs the nonce to recover the
    /// plaintext.
    pub fn seal(&self, plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>), SealingKeyError> {
        let cipher = self.cipher()?;
        let mut nonce_bytes = [0u8; NONCE_LEN];
        getrandom::fill(&mut nonce_bytes)
            .map_err(|e| SealingKeyError::NonceGenFailed(e.to_string()))?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ct = cipher
            .encrypt(nonce, plaintext)
            .map_err(|_| SealingKeyError::Decrypt)?; // encrypt rarely errors; fold into Decrypt
        Ok((ct, nonce_bytes.to_vec()))
    }

    /// Unseal a ciphertext using the supplied nonce. Returns the
    /// plaintext bytes. Authentication failure (wrong key, tampered
    /// ciphertext, corrupt nonce) returns `Err(Decrypt)`.
    pub fn unseal(&self, ciphertext: &[u8], nonce: &[u8]) -> Result<Vec<u8>, SealingKeyError> {
        if nonce.len() != NONCE_LEN {
            return Err(SealingKeyError::InvalidNonce(nonce.len()));
        }
        let cipher = self.cipher()?;
        cipher
            .decrypt(Nonce::from_slice(nonce), ciphertext)
            .map_err(|_| SealingKeyError::Decrypt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_unseal_roundtrip() {
        let key = SealingKey::generate().unwrap();
        let plaintext = b"refresh-token-abc-123";
        let (ct, nonce) = key.seal(plaintext).unwrap();
        let recovered = key.unseal(&ct, &nonce).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn seal_produces_unique_ciphertexts() {
        let key = SealingKey::generate().unwrap();
        let plaintext = b"same-plaintext";
        let (ct1, nonce1) = key.seal(plaintext).unwrap();
        let (ct2, nonce2) = key.seal(plaintext).unwrap();
        assert_ne!(ct1, ct2, "fresh nonce should yield distinct ciphertexts");
        assert_ne!(nonce1, nonce2);
    }

    #[test]
    fn unseal_with_wrong_key_fails() {
        let k1 = SealingKey::generate().unwrap();
        let k2 = SealingKey::generate().unwrap();
        let (ct, nonce) = k1.seal(b"secret").unwrap();
        let err = k2.unseal(&ct, &nonce).unwrap_err();
        assert!(matches!(err, SealingKeyError::Decrypt));
    }

    #[test]
    fn unseal_with_tampered_ciphertext_fails() {
        let key = SealingKey::generate().unwrap();
        let (mut ct, nonce) = key.seal(b"secret").unwrap();
        ct[0] ^= 0xff; // flip a bit
        let err = key.unseal(&ct, &nonce).unwrap_err();
        assert!(matches!(err, SealingKeyError::Decrypt));
    }

    #[test]
    fn from_b64_rejects_wrong_length() {
        let too_short = B64.encode([0u8; 16]);
        let err = SealingKey::from_b64(&too_short).unwrap_err();
        assert!(matches!(err, SealingKeyError::InvalidLength(16)));
    }

    #[test]
    fn from_b64_rejects_invalid_base64() {
        let err = SealingKey::from_b64("not-valid-base64!!!").unwrap_err();
        assert!(matches!(err, SealingKeyError::InvalidBase64(_)));
    }

    #[test]
    fn unseal_rejects_short_nonce() {
        let key = SealingKey::generate().unwrap();
        let err = key.unseal(b"ciphertext", &[0u8; 8]).unwrap_err();
        assert!(matches!(err, SealingKeyError::InvalidNonce(8)));
    }
}
