//! Integration test binary: admin API, audit, operational logs, repositories, migrations and CLI.
//!
//! Each module is one former test binary, included unchanged by path, so its
//! own `mod` declarations still resolve beside it. Run one with
//! `cargo test --test admin_suite <module>::`. See docs/development/local-ci.md.

// Each former binary keeps its own private copy of shared helper files, as it
// did when it was a separate binary.
#![allow(clippy::duplicate_mod)]

#[path = "admin_config_test.rs"]
mod admin_config_test;
#[path = "admin_uds_test.rs"]
mod admin_uds_test;
#[path = "audit_admin_test.rs"]
mod audit_admin_test;
#[path = "audit_auth_method_test.rs"]
mod audit_auth_method_test;
#[path = "audit_failure_test.rs"]
mod audit_failure_test;
#[path = "audit_jsonl_test.rs"]
mod audit_jsonl_test;
#[path = "audit_proxy_test.rs"]
mod audit_proxy_test;
#[path = "audit_retention_test.rs"]
mod audit_retention_test;
#[path = "bootstrap_only_listener_test.rs"]
mod bootstrap_only_listener_test;
#[path = "config_strict_test.rs"]
mod config_strict_test;
#[path = "config_test.rs"]
mod config_test;
#[path = "credential_rekey_test.rs"]
mod credential_rekey_test;
#[path = "credential_store_admin_test.rs"]
mod credential_store_admin_test;
#[path = "deprecation_test.rs"]
mod deprecation_test;
#[path = "migrations_test.rs"]
mod migrations_test;
#[path = "operational_log_admin_test.rs"]
mod operational_log_admin_test;
#[path = "operational_log_retention_test.rs"]
mod operational_log_retention_test;
#[path = "repo_test.rs"]
mod repo_test;
#[path = "test_inventory_test.rs"]
mod test_inventory_test;
#[path = "tool_activation_test.rs"]
mod tool_activation_test;
#[path = "uds_client_test.rs"]
mod uds_client_test;
