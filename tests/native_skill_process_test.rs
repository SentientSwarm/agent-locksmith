//! Actual daemon guidance, discovery and useful mixed-protocol effects.
#![allow(dead_code)]
#[path = "native_process/fixture.rs"]
mod fixture;
#[path = "native_preparation/process_flow.rs"]
mod flow;
#[path = "native_skill/process.rs"]
mod journey;
#[path = "native_process/observations.rs"]
mod observations;
#[path = "native_process/pki.rs"]
mod pki;
#[path = "explicit_binding_smoke/process.rs"]
mod process;
#[path = "native_context/receiving.rs"]
mod receiver;
#[path = "native_context/process_support.rs"]
mod support;
#[path = "native_process/wire.rs"]
mod wire;

#[path = "native_skill/snapshot.rs"]
mod snapshot;
