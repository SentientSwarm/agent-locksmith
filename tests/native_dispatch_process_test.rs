#![allow(dead_code)]
#[path = "native_dispatch/discovery.rs"]
mod discovery;
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
#[path = "native_dispatch/receiver.rs"]
mod receiver;
#[path = "native_process/wire.rs"]
mod wire;

#[path = "native_dispatch/calls.rs"]
mod calls;

#[path = "native_dispatch/commit.rs"]
mod commit;

#[path = "native_dispatch/clients.rs"]
mod clients;

#[path = "native_dispatch/upgrade.rs"]
mod upgrade;

#[path = "native_dispatch/results.rs"]
mod results;

#[path = "native_dispatch/lifecycle.rs"]
mod lifecycle;
