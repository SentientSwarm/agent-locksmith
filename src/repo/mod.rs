//! Repositories — type-safe SQL access for M2 entities.
//! See SPEC §4.3.5.

pub mod agent;
pub mod audit;
pub mod bootstrap;

pub use agent::{AgentRecord, AgentRepository, RepoError};
pub use audit::{AuditEvent, AuditFilter, AuditPage, AuditRepository, Decision, EventClass};
pub use bootstrap::{BootstrapScope, BootstrapTokenRecord, BootstrapTokenRepository};
