//! Integration test binary: tests that start real locksmithd or CLI processes.
//!
//! Each module is one former test binary, included unchanged by path, so its
//! own `mod` declarations still resolve beside it. Run one with
//! `cargo test --test daemon_suite <module>::`. See docs/development/local-ci.md.

// Each former binary keeps its own private copy of shared helper files, as it
// did when it was a separate binary.
#![allow(clippy::duplicate_mod)]

#[path = "admin_https_mtls_e2e_test.rs"]
mod admin_https_mtls_e2e_test;
#[path = "bootstrap_only_daemon_test.rs"]
mod bootstrap_only_daemon_test;
#[path = "broker_daemon_test.rs"]
mod broker_daemon_test;
#[path = "cli_e2e_test.rs"]
mod cli_e2e_test;
#[path = "credential_store_e2e_test.rs"]
mod credential_store_e2e_test;
#[path = "daemon_listener_startup_test.rs"]
mod daemon_listener_startup_test;
#[path = "daemon_runtime_test.rs"]
mod daemon_runtime_test;
#[path = "mtls_revocation_daemon_test.rs"]
mod mtls_revocation_daemon_test;
#[path = "native_compact_sdk_test.rs"]
mod native_compact_sdk_test;
#[path = "native_context_process_test.rs"]
mod native_context_process_test;
#[path = "native_dispatch_process_test.rs"]
mod native_dispatch_process_test;
#[path = "native_skill_process_test.rs"]
mod native_skill_process_test;
