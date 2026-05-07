//! T6.7 — operator authentication by mTLS cert_identity.

use agent_locksmith::auth_v2::OperatorAuthenticator;
use std::io::Write;
use tempfile::NamedTempFile;

fn write_operators(yaml: &str) -> NamedTempFile {
    let mut f = NamedTempFile::new().unwrap();
    f.write_all(yaml.as_bytes()).unwrap();
    f
}

#[tokio::test]
async fn cert_identity_resolves_to_operator() {
    let f = write_operators(
        r#"
operators:
  - name: alice
    public_id: "lkop_aaaa"
    token_hash: "$argon2id$v=19$m=4096,t=3,p=1$c2FsdHNhbHQ$dGVzdHRlc3R0ZXN0"
    cert_identity: "alice@example.com"
"#,
    );
    let auth = OperatorAuthenticator::load(f.path()).expect("loads");
    let id = auth
        .authenticate_cert_identity("alice@example.com")
        .await
        .unwrap();
    assert_eq!(id.name, "alice");
}

#[tokio::test]
async fn unknown_cert_identity_is_invalid() {
    let f = write_operators(
        r#"
operators:
  - name: bob
    public_id: "lkop_bbbb"
    token_hash: "$argon2id$v=19$m=4096,t=3,p=1$c2FsdHNhbHQ$dGVzdHRlc3R0ZXN0"
    cert_identity: "bob@example.com"
"#,
    );
    let auth = OperatorAuthenticator::load(f.path()).unwrap();
    let err = auth
        .authenticate_cert_identity("ghost@example.com")
        .await
        .unwrap_err();
    assert_eq!(err.code(), "invalid_credential");
}

#[tokio::test]
async fn operator_without_cert_identity_does_not_match_anything() {
    let f = write_operators(
        r#"
operators:
  - name: carol
    public_id: "lkop_cccc"
    token_hash: "$argon2id$v=19$m=4096,t=3,p=1$c2FsdHNhbHQ$dGVzdHRlc3R0ZXN0"
"#,
    );
    let auth = OperatorAuthenticator::load(f.path()).unwrap();
    // Even with the operator's name as the cert_identity, no match —
    // operator must explicitly opt in to mTLS by setting cert_identity.
    let err = auth.authenticate_cert_identity("carol").await.unwrap_err();
    assert_eq!(err.code(), "invalid_credential");
}
