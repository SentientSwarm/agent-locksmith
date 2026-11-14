//! Integration test binary: the agent proxy hot path, response controls and credential sources.
//!
//! Each module is one former test binary, included unchanged by path, so its
//! own `mod` declarations still resolve beside it. Run one with
//! `cargo test --test proxy_suite <module>::`. See docs/development/local-ci.md.

// Each former binary keeps its own private copy of shared helper files, as it
// did when it was a separate binary.
#![allow(clippy::duplicate_mod)]

#[path = "agent_stored_override_test.rs"]
mod agent_stored_override_test;
#[path = "auth_test.rs"]
mod auth_test;
#[path = "auth_v2_test.rs"]
mod auth_v2_test;
#[path = "credential_store_proxy_test.rs"]
mod credential_store_proxy_test;
#[path = "discovery_test.rs"]
mod discovery_test;
#[path = "health_test.rs"]
mod health_test;
#[path = "identityless_isolation_test.rs"]
mod identityless_isolation_test;
#[path = "inference_matrix_local_test.rs"]
mod inference_matrix_local_test;
#[path = "integration_test.rs"]
mod integration_test;
#[path = "m2_integration_test.rs"]
mod m2_integration_test;
#[path = "op_credential_proxy_test.rs"]
mod op_credential_proxy_test;
#[path = "op_source_safety_test.rs"]
mod op_source_safety_test;
#[path = "proxy_acl_test.rs"]
mod proxy_acl_test;
#[path = "proxy_redirect_test.rs"]
mod proxy_redirect_test;
#[path = "proxy_test.rs"]
mod proxy_test;
#[path = "response_controls_apply_test.rs"]
mod response_controls_apply_test;
#[path = "response_controls_config_test.rs"]
mod response_controls_config_test;
#[path = "response_controls_content_type_test.rs"]
mod response_controls_content_type_test;
#[path = "response_controls_redaction_test.rs"]
mod response_controls_redaction_test;
#[path = "response_controls_size_test.rs"]
mod response_controls_size_test;
#[path = "response_controls_streaming_test.rs"]
mod response_controls_streaming_test;
#[path = "revoke_cascade_test.rs"]
mod revoke_cascade_test;
#[path = "secret_backend_file_sealed_test.rs"]
mod secret_backend_file_sealed_test;
#[path = "secret_backend_stubs_test.rs"]
mod secret_backend_stubs_test;
#[path = "secret_ref_parse_test.rs"]
mod secret_ref_parse_test;
#[path = "skill_guidance_test.rs"]
mod skill_guidance_test;
#[path = "skill_test.rs"]
mod skill_test;
#[path = "streaming_passthrough_test.rs"]
mod streaming_passthrough_test;
#[path = "upstream_ca_route_test.rs"]
mod upstream_ca_route_test;
