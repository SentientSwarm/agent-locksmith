#![allow(dead_code)] // Adapter exposes the unchanged historical assertion interface.
const COMPACT: bool = true;
extern crate self as locksmith_mcp_authority_proof;
pub type Error = Box<dyn std::error::Error + Send + Sync>;
#[path = "native_dispatch/glue/fixture.rs"]
pub mod fixture;
#[path = "native/fixture.rs"]
mod native;
#[path = "native_dispatch/glue/observers.rs"]
mod observers;
#[path = "native_process/pki.rs"]
mod pki;
#[path = "explicit_binding_smoke/process.rs"]
mod process;
#[path = "native_dispatch/glue/setup.rs"]
mod setup;
#[path = "native_preparation/support.rs"]
mod support;
#[path = "native_compact/original_wire.rs"]
pub mod wire;
#[rustfmt::skip]
#[path="native_dispatch/original_disconnect_wait.rs"]
mod original;

#[path = "native_oauth/fixture.rs"]
mod controlled;
