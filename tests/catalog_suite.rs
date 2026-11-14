//! Integration test binary: registrations, HTTP services, routes, brokers, definitions and bindings.
//!
//! Each module is one former test binary, included unchanged by path, so its
//! own `mod` declarations still resolve beside it. Run one with
//! `cargo test --test catalog_suite <module>::`. See docs/development/local-ci.md.

// Each former binary keeps its own private copy of shared helper files, as it
// did when it was a separate binary.
#![allow(clippy::duplicate_mod)]

#[path = "binding_migration_test.rs"]
mod binding_migration_test;
#[path = "broker_backend_test.rs"]
mod broker_backend_test;
#[path = "broker_hardening_test.rs"]
mod broker_hardening_test;
#[path = "broker_health_test.rs"]
mod broker_health_test;
#[path = "broker_proxy_test.rs"]
mod broker_proxy_test;
#[path = "broker_route_test.rs"]
mod broker_route_test;
#[path = "connector_destination_test.rs"]
mod connector_destination_test;
#[path = "definition_api_test.rs"]
mod definition_api_test;
#[path = "definition_validation_test.rs"]
mod definition_validation_test;
#[path = "http_activation_test.rs"]
mod http_activation_test;
#[path = "http_grants_test.rs"]
mod http_grants_test;
#[path = "http_service_descriptor_test.rs"]
mod http_service_descriptor_test;
#[path = "http_service_seed_test.rs"]
mod http_service_seed_test;
#[path = "phase_e_admin_test.rs"]
mod phase_e_admin_test;
#[path = "phase_e_authless_test.rs"]
mod phase_e_authless_test;
#[path = "phase_e_discovery_test.rs"]
mod phase_e_discovery_test;
#[path = "phase_e_migration_test.rs"]
mod phase_e_migration_test;
#[path = "phase_e_seed_loader_test.rs"]
mod phase_e_seed_loader_test;
#[path = "phase_e_validators_test.rs"]
mod phase_e_validators_test;
#[path = "phase_g3_codex_body_test.rs"]
mod phase_g3_codex_body_test;
#[path = "phase_g4_codex_headers_test.rs"]
mod phase_g4_codex_headers_test;
#[path = "phase_j_review_fixes_test.rs"]
mod phase_j_review_fixes_test;
#[path = "route_backend_api_test.rs"]
mod route_backend_api_test;
#[path = "route_backend_followups_test.rs"]
mod route_backend_followups_test;
#[path = "route_backend_switch_test.rs"]
mod route_backend_switch_test;
#[path = "route_profile_test.rs"]
mod route_profile_test;
