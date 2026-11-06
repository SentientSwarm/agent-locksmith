//! Finite response bounds for rmcp 3.7.0; daemon integration is separate.
mod body;
mod client;
mod error;
mod headers;
mod json;
mod limits;
mod metrics;
mod operations;
mod post;
mod request;
mod sse;
mod sse_guard;
mod transport;

pub use client::Client;
pub use error::{Error, io_code};
pub use limits::Limits;
pub use metrics::{Metrics, Snapshot};

/// Scoped SDK session ownership and finite resource budgets.
pub mod sessions;

mod pinned;
pub mod strict_json;
pub use reqwest::Certificate;
pub type ResponseValidator = fn(&serde_json::Value) -> Result<(), Error>;
