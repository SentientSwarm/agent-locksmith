//! T2.19 — EnvBackend resolves LegacyString and FromEnv variants.
//!
//! Concurrency note: these tests mutate `std::env`, which is a
//! process-global. Each test uses a unique env-var name (with the test
//! function name as suffix) to avoid cross-test pollution when the
//! suite runs in parallel.

use agent_locksmith::secret::{BackendError, EnvBackend, SecretBackend, SecretRef};
use secrecy::ExposeSecret;
use std::path::PathBuf;

fn unique(name: &str) -> String {
    format!("LOCKSMITH_TEST_{}_{}", name, std::process::id())
}

#[tokio::test]
async fn from_env_happy_path() {
    let var = unique("FROM_ENV_HAPPY");
    // SAFETY: tests are intentionally manipulating env; var name is
    // unique per test to avoid cross-test interference.
    unsafe { std::env::set_var(&var, "shhh") };
    let backend = EnvBackend::new();
    let resolved = backend
        .resolve(&SecretRef::FromEnv {
            var: var.clone(),
            prefix: None,
        })
        .await
        .expect("resolve ok");
    assert_eq!(resolved.expose_secret(), "shhh");
    unsafe { std::env::remove_var(&var) };
}

#[tokio::test]
async fn from_env_with_prefix_concatenates() {
    let var = unique("FROM_ENV_PREFIX");
    unsafe { std::env::set_var(&var, "abc123") };
    let backend = EnvBackend::new();
    let resolved = backend
        .resolve(&SecretRef::FromEnv {
            var: var.clone(),
            prefix: Some("Bearer ".to_string()),
        })
        .await
        .unwrap();
    assert_eq!(resolved.expose_secret(), "Bearer abc123");
    unsafe { std::env::remove_var(&var) };
}

#[tokio::test]
async fn from_env_missing_var_returns_missing() {
    let var = unique("FROM_ENV_MISSING");
    // Ensure it's actually unset (set_var/remove_var round-trip safety).
    unsafe { std::env::remove_var(&var) };
    let backend = EnvBackend::new();
    let err = backend
        .resolve(&SecretRef::FromEnv {
            var: var.clone(),
            prefix: None,
        })
        .await
        .unwrap_err();
    match err {
        BackendError::Missing(name) => assert_eq!(name, var),
        other => panic!("expected Missing, got {other:?}"),
    }
}

#[tokio::test]
async fn legacy_string_textual_expansion() {
    let var = unique("LEGACY_EXPAND");
    unsafe { std::env::set_var(&var, "topsecret") };
    let backend = EnvBackend::new();
    let resolved = backend
        .resolve(&SecretRef::LegacyString(format!("Bearer ${{{var}}}")))
        .await
        .unwrap();
    assert_eq!(resolved.expose_secret(), "Bearer topsecret");
    unsafe { std::env::remove_var(&var) };
}

#[tokio::test]
async fn legacy_string_missing_var_expands_to_empty() {
    // Match the M0 expander's behavior: missing vars become empty.
    // Existing configs that relied on this don't regress.
    let var = unique("LEGACY_MISSING");
    unsafe { std::env::remove_var(&var) };
    let backend = EnvBackend::new();
    let resolved = backend
        .resolve(&SecretRef::LegacyString(format!("X${{{var}}}Y")))
        .await
        .unwrap();
    assert_eq!(resolved.expose_secret(), "XY");
}

#[tokio::test]
async fn env_backend_rejects_file_sealed_variant() {
    let backend = EnvBackend::new();
    let err = backend
        .resolve(&SecretRef::FromFileSealed {
            path: PathBuf::from("/dev/null"),
        })
        .await
        .unwrap_err();
    assert!(matches!(err, BackendError::NotImplemented(_)));
}
