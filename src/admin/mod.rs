//! Admin business logic and listener wiring.
//!
//! `service` holds the transport-independent business logic — every
//! admin operation is a method on `AdminService` that takes typed
//! inputs and returns typed outputs. The same service is consumed by
//! the M2 admin UDS listener (`uds`), and (post-M2) by the M4 admin
//! HTTPS listener and the M6 bootstrap-only listener.

pub mod https;
pub mod service;
pub mod uds;
pub mod uds_client;

pub use service::{AdminError, AdminService, RegisterInput, RegisterOutput};
