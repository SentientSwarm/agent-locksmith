//! Native MCP lifecycle. Connection authority never implies a tool grant.
pub mod config;
mod context;
mod error;
mod handler;
mod ingress;
pub(crate) mod json;
mod manager;
mod response;
mod route;
mod runtime;
mod wire;

pub use ingress::boundary;
pub use route::endpoint;
pub use runtime::Runtime;
mod audit;

mod input;
mod scope;
mod sdk;
