//! Integration test binary: in-process native MCP lifecycle, policy and dispatch.
//!
//! Each module is one former test binary, included unchanged by path, so its
//! own `mod` declarations still resolve beside it. Run one with
//! `cargo test --test native_suite <module>::`. See docs/development/local-ci.md.

// Each former binary keeps its own private copy of shared helper files, as it
// did when it was a separate binary.
#![allow(clippy::duplicate_mod)]

#[path = "native_boundaries_test.rs"]
mod native_boundaries_test;
#[path = "native_configuration_test.rs"]
mod native_configuration_test;
#[path = "native_context_test.rs"]
mod native_context_test;
#[path = "native_dispatch_test.rs"]
mod native_dispatch_test;
#[path = "native_error_ids_test.rs"]
mod native_error_ids_test;
#[path = "native_lifecycle_test.rs"]
mod native_lifecycle_test;
#[path = "native_policy_test.rs"]
mod native_policy_test;
#[path = "native_preparation_test.rs"]
mod native_preparation_test;
#[path = "native_registration_test.rs"]
mod native_registration_test;
#[path = "native_skill_test.rs"]
mod native_skill_test;
#[path = "native_state_test.rs"]
mod native_state_test;
