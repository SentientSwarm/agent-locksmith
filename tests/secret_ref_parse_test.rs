//! T2.17 — SecretRef enum parses both legacy (plain string) and typed
//! (tagged map) forms.
//!
//! Backward-compat is non-negotiable: every existing M0/M1 config that
//! used `value: "Bearer ${TOKEN}"` keeps working, parsing as
//! `SecretRef::LegacyString`. Typed forms are tagged maps with a single
//! `from_*` key.

use agent_locksmith::secret::SecretRef;

fn parse(yaml: &str) -> SecretRef {
    serde_yaml::from_str(yaml).expect("parse ok")
}

#[test]
fn legacy_plain_string_parses_as_legacy_variant() {
    let sr = parse(r#""Bearer ${API_KEY}""#);
    match sr {
        SecretRef::LegacyString(s) => assert_eq!(s, "Bearer ${API_KEY}"),
        other => panic!("expected LegacyString, got {other:?}"),
    }
}

#[test]
fn empty_string_parses_as_legacy_empty() {
    let sr = parse(r#""""#);
    match sr {
        SecretRef::LegacyString(s) => assert!(s.is_empty()),
        other => panic!("expected LegacyString, got {other:?}"),
    }
}

#[test]
fn from_env_with_var_only() {
    let sr = parse("from_env:\n  var: API_KEY");
    match sr {
        SecretRef::FromEnv { var, prefix } => {
            assert_eq!(var, "API_KEY");
            assert!(prefix.is_none());
        }
        other => panic!("expected FromEnv, got {other:?}"),
    }
}

#[test]
fn from_env_with_prefix() {
    let sr = parse("from_env:\n  var: API_KEY\n  prefix: \"Bearer \"");
    match sr {
        SecretRef::FromEnv { var, prefix } => {
            assert_eq!(var, "API_KEY");
            assert_eq!(prefix.as_deref(), Some("Bearer "));
        }
        other => panic!("expected FromEnv, got {other:?}"),
    }
}

#[test]
fn from_file_sealed_with_path() {
    let sr = parse("from_file_sealed:\n  path: /run/credentials/locksmith/api_key");
    match sr {
        SecretRef::FromFileSealed { path } => {
            assert_eq!(path.to_str(), Some("/run/credentials/locksmith/api_key"));
        }
        other => panic!("expected FromFileSealed, got {other:?}"),
    }
}

#[test]
fn from_vault_with_full_address() {
    let sr = parse("from_vault:\n  mount: secret\n  path: prod/locksmith\n  field: api_key");
    match sr {
        SecretRef::FromVault { mount, path, field } => {
            assert_eq!(mount, "secret");
            assert_eq!(path, "prod/locksmith");
            assert_eq!(field, "api_key");
        }
        other => panic!("expected FromVault, got {other:?}"),
    }
}

#[test]
fn from_aws_secrets_manager_minimal() {
    let sr = parse("from_aws_secrets_manager:\n  secret_id: prod/locksmith/api_key");
    match sr {
        SecretRef::FromAwsSecretsManager {
            secret_id,
            version_stage,
            field,
        } => {
            assert_eq!(secret_id, "prod/locksmith/api_key");
            assert!(version_stage.is_none());
            assert!(field.is_none());
        }
        other => panic!("expected FromAwsSecretsManager, got {other:?}"),
    }
}

#[test]
fn unknown_tag_is_rejected() {
    let result: Result<SecretRef, _> = serde_yaml::from_str("from_consul:\n  key: foo");
    assert!(
        result.is_err(),
        "unknown variant tag must fail to parse, got {:?}",
        result.ok()
    );
}
