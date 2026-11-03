//! AGENT-178: actual offline CLI, synthetic SQLite and upstream only.
#[path = "binding_migration/contracts.rs"]
mod contracts;
#[path = "binding_migration/drift.rs"]
mod drift;
#[path = "binding_migration/fixture.rs"]
mod fixture;
#[path = "binding_migration/inventory.rs"]
mod inventory;
#[path = "binding_migration/legacy_contracts.rs"]
mod legacy_contracts;
#[path = "binding_migration/legacy_runtime.rs"]
mod legacy_runtime;
#[path = "binding_migration/metadata.rs"]
mod metadata;
#[path = "binding_migration/oauth.rs"]
mod oauth;
#[path = "binding_migration/receipts.rs"]
mod receipts;
#[path = "binding_migration/runtime.rs"]
mod runtime;
