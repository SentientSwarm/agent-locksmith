//! Integration test binary: mTLS validation, revocation and the admin HTTPS listener.
//!
//! Each module is one former test binary, included unchanged by path, so its
//! own `mod` declarations still resolve beside it. Run one with
//! `cargo test --test mtls_suite <module>::`. See docs/development/local-ci.md.

// Each former binary keeps its own private copy of shared helper files, as it
// did when it was a separate binary.
#![allow(clippy::duplicate_mod)]

#[path = "admin_https_off_by_default_test.rs"]
mod admin_https_off_by_default_test;
#[path = "admin_https_pem_load_test.rs"]
mod admin_https_pem_load_test;
#[path = "admin_https_test.rs"]
mod admin_https_test;
#[path = "cli_admin_https_test.rs"]
mod cli_admin_https_test;
#[path = "cli_mtls_test.rs"]
mod cli_mtls_test;
#[path = "cli_set_cert_identity_test.rs"]
mod cli_set_cert_identity_test;
#[path = "mtls_authenticator_test.rs"]
mod mtls_authenticator_test;
#[path = "mtls_blocklist_test.rs"]
mod mtls_blocklist_test;
#[path = "mtls_config_test.rs"]
mod mtls_config_test;
#[path = "mtls_crl_test.rs"]
mod mtls_crl_test;
#[path = "mtls_validator_test.rs"]
mod mtls_validator_test;
#[path = "operator_mtls_test.rs"]
mod operator_mtls_test;
