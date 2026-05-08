//! mTLS support (M6, C-16). Cert validation, CRL fetcher, local
//! emergency blocklist, and the `MtlsAuthenticator` that ties them
//! together for the agent + operator surfaces.
//!
//! The threat model for this module:
//! - We validate every leaf cert against a configured CA bundle (T6.2).
//! - We refresh a CRL periodically; revoked serials are rejected (T6.3).
//! - We honor a local emergency blocklist for incident response (T6.4).
//! - The validated identity is mapped to an agent record by
//!   `AgentRepository.get_by_cert_identity` (T6.5).
//!
//! Verification gate: T6.2 (validator) + T6.5 (authenticator). Each
//! gate's review is in the per-task commit message.

pub mod authenticator;
pub mod blocklist;
pub mod crl;
pub mod validator;

pub use authenticator::MtlsAuthenticator;
pub use blocklist::Blocklist;
pub use crl::{CrlState, CrlStore};
pub use validator::{MtlsError, MtlsIdentity, MtlsValidator};
