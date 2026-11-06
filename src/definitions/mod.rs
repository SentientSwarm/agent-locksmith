//! Immutable offline integration authoring; no credentials or execution.
pub mod api;
mod builtin;
pub(crate) mod eligibility;
mod instance;
pub(crate) mod promotion;
mod types;
pub mod validate;
use sha2::{Digest, Sha256};
pub use types::*;

pub const MAX_BYTES: usize = 64 * 1024;
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid or unsupported integration definition input")]
    Invalid,
    #[error("definition revision or connection already exists with different state")]
    Conflict,
    #[error("exact definition revision not found")]
    NotFound,
    #[error("current definition revision precondition required")]
    Precondition,
    #[error(
        "configuration saved; runtime pending. Read fresh state, then retry with its current revision or restart"
    )]
    SavedUnavailable,
    #[error("definition operation unavailable; read fresh state before repair")]
    Unavailable,
    #[error("definition storage unavailable")]
    Backend,
}
impl From<sqlx::Error> for Error {
    fn from(_: sqlx::Error) -> Self {
        Self::Backend
    }
}
pub fn parse(bytes: &[u8]) -> Result<Definition, Error> {
    let definition: Definition = decode(bytes)?;
    validate::definition(&definition)?;
    builtin::check(&definition)?;
    Ok(definition)
}
pub fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, Error> {
    if bytes.len() > MAX_BYTES {
        return Err(Error::Invalid);
    }
    let value = crate::native::json::parse(bytes).map_err(|_| Error::Invalid)?;
    serde_json::from_value(value).map_err(|_| Error::Invalid)
}
impl Definition {
    pub fn canonical(&self) -> Result<String, Error> {
        serde_json::to_string(self).map_err(|_| Error::Invalid)
    }
    pub fn digest(&self) -> Result<String, Error> {
        let mut hash = Sha256::new();
        hash.update(b"locksmith-integration-v1\0");
        hash.update(self.canonical()?.as_bytes());
        Ok(format!("{:x}", hash.finalize()))
    }
}
