#![allow(dead_code)]
#[path = "native_context/process_calls.rs"]
mod calls;
#[path = "native_process/fixture.rs"]
mod fixture;
#[path = "native_preparation/process_flow.rs"]
mod flow;
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

#[path = "native_context/outcomes.rs"]
mod outcomes;
#[path = "native_context/secrets.rs"]
mod secrets;
#[path = "native_context/upgrade.rs"]
mod upgrade;

#[path = "native_context/admission.rs"]
mod admission;
#[path = "native_context/tamper.rs"]
mod tamper;
