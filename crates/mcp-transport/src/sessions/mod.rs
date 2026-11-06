//! Stateful, non-resumable rmcp sessions. Scopes come from verified application
//! authority; this library does not authenticate HTTP input.
mod config;
mod entry;
mod lifecycle;
mod manager;
mod operations;
mod pool;
mod stream;
mod transport;

pub use config::{Config, Scope};
pub use pool::{Pool, Scoped, Snapshot};
pub use transport::OwnedTransport;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid session configuration")]
    Config,
    #[error("session capacity exhausted")]
    Capacity,
    #[error("session unavailable")]
    Unavailable,
    #[error("session operation limit exceeded")]
    Limit,
    #[error("session resumption is unsupported")]
    Resume,
    #[error("session transport failed")]
    Transport,
}
