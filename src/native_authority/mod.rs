//! Operator preparation of finite native authority. Agent dispatch stays disabled.
pub mod contract;
mod numbers;
pub mod schema;

#[derive(Debug, Clone, Copy, thiserror::Error)]
#[error("{0}")]
pub struct Error(pub &'static str);
pub type Result<T> = std::result::Result<T, Error>;

pub mod source;
pub mod store;

impl From<sqlx::Error> for Error {
    fn from(_: sqlx::Error) -> Self {
        Self("backend_unavailable")
    }
}

pub mod grants;

pub mod destination;
mod interfaces;

mod wire;

pub mod api;
mod observe;
pub mod runtime;
pub mod writes;

mod wire_format;

#[cfg(test)]
pub(crate) mod body_probe;
mod body_scope;
