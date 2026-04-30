//! Argon2id password-style hashing helpers for token secrets.
//!
//! T2.8 / INF-5 / R-N2. Q-13 resolution: `m=4 MiB, t=3, p=1` — token-tuned
//! parameters that give ~5ms verification cost on commodity hardware. The
//! 256-bit random secret behind every Locksmith token (`token::Secret`)
//! has 1.16e77 entropy, so argon2's memory-hardness is defense-in-depth
//! rather than the primary defense.
//!
//! All input is `&secrecy::SecretString`; the underlying byte slice is
//! never logged or otherwise exposed beyond the verify call. Hash output
//! is a self-describing PHC string that can be stored as TEXT.

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use secrecy::{ExposeSecret, SecretString};

#[derive(Debug, thiserror::Error)]
pub enum HashError {
    #[error("argon2 hash: {0}")]
    Hash(argon2::password_hash::Error),
    #[error("argon2 verify: {0}")]
    Verify(argon2::password_hash::Error),
    #[error("argon2 params: {0}")]
    Params(argon2::Error),
}

fn argon2() -> Result<Argon2<'static>, HashError> {
    // Q-13: m=4 MiB, t=3, p=1. Output 32 bytes (256-bit derived key).
    // 4 MiB = 4096 KiB.
    let params = Params::new(4096, 3, 1, Some(32)).map_err(HashError::Params)?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}

/// Hash `secret` with argon2id and return the PHC-format string.
pub fn hash(secret: &SecretString) -> Result<String, HashError> {
    let mut salt_bytes = [0u8; 16];
    getrandom::fill(&mut salt_bytes).expect("OS RNG unavailable");
    let salt = SaltString::encode_b64(&salt_bytes).map_err(HashError::Hash)?;
    let hasher = argon2()?;
    let phc = hasher
        .hash_password(secret.expose_secret().as_bytes(), &salt)
        .map_err(HashError::Hash)?;
    Ok(phc.to_string())
}

/// Constant-time verify `secret` against `phc_hash`. Returns `Ok(true)` on
/// match, `Ok(false)` on mismatch, `Err` only on malformed hash strings.
pub fn verify(phc_hash: &str, secret: &SecretString) -> Result<bool, HashError> {
    let parsed = PasswordHash::new(phc_hash).map_err(HashError::Hash)?;
    let hasher = argon2()?;
    match hasher.verify_password(secret.expose_secret().as_bytes(), &parsed) {
        Ok(()) => Ok(true),
        Err(argon2::password_hash::Error::Password) => Ok(false),
        Err(e) => Err(HashError::Verify(e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_verify_roundtrip() {
        let s = SecretString::from("correct-horse-battery-staple".to_string());
        let h = hash(&s).expect("hash ok");
        assert!(verify(&h, &s).expect("verify ok"));
    }

    #[test]
    fn verify_rejects_wrong_secret() {
        let h = hash(&SecretString::from("real".to_string())).expect("hash ok");
        let bad = SecretString::from("fake".to_string());
        assert!(!verify(&h, &bad).expect("verify ok"));
    }

    #[test]
    fn hash_includes_argon2id_marker() {
        let h = hash(&SecretString::from("x".to_string())).expect("hash ok");
        assert!(h.starts_with("$argon2id$"));
    }

    #[test]
    fn each_hash_uses_unique_salt() {
        let s = SecretString::from("same-secret".to_string());
        let a = hash(&s).expect("hash ok");
        let b = hash(&s).expect("hash ok");
        assert_ne!(a, b, "salts must differ between hashes");
        // Both should still verify against the same secret.
        assert!(verify(&a, &s).expect("verify ok"));
        assert!(verify(&b, &s).expect("verify ok"));
    }
}
