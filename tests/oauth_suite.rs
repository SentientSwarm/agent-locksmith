//! Integration test binary: OAuth admin, serde, seeding, device login and recovery.
//!
//! Each module is one former test binary, included unchanged by path, so its
//! own `mod` declarations still resolve beside it. Run one with
//! `cargo test --test oauth_suite <module>::`. See docs/development/local-ci.md.

// Each former binary keeps its own private copy of shared helper files, as it
// did when it was a separate binary.
#![allow(clippy::duplicate_mod)]

#[path = "oauth_consent_test.rs"]
mod oauth_consent_test;
#[path = "oauth_device_login_test.rs"]
mod oauth_device_login_test;
#[path = "oauth_incarnation_test.rs"]
mod oauth_incarnation_test;
#[path = "oauth_recovery_test.rs"]
mod oauth_recovery_test;
#[path = "phase_f_oauth_admin_test.rs"]
mod phase_f_oauth_admin_test;
#[path = "phase_f_oauth_serde_test.rs"]
mod phase_f_oauth_serde_test;
#[path = "phase_f_seed_oauth_test.rs"]
mod phase_f_seed_oauth_test;
