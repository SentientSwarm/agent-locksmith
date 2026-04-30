//! T5.3 — Vault + AwsSecretsManager backends are constructible stubs
//! that return `NotImplemented` from `resolve`.

use agent_locksmith::secret::{
    AwsSecretsManagerBackend, BackendError, SecretBackend, SecretRef, VaultBackend,
};

#[tokio::test]
async fn vault_stub_returns_not_implemented() {
    let backend = VaultBackend::new(Some("https://vault.example.com:8200".into()));
    assert_eq!(backend.kind(), "vault");
    let err = backend
        .resolve(&SecretRef::FromVault {
            mount: "secret".into(),
            path: "prod/locksmith".into(),
            field: "api_key".into(),
        })
        .await
        .unwrap_err();
    assert!(matches!(err, BackendError::NotImplemented(_)));
}

#[tokio::test]
async fn aws_stub_returns_not_implemented() {
    let backend = AwsSecretsManagerBackend::new(Some("us-west-2".into()));
    assert_eq!(backend.kind(), "aws_secrets_manager");
    let err = backend
        .resolve(&SecretRef::FromAwsSecretsManager {
            secret_id: "prod/locksmith/api_key".into(),
            version_stage: None,
            field: None,
        })
        .await
        .unwrap_err();
    assert!(matches!(err, BackendError::NotImplemented(_)));
}
