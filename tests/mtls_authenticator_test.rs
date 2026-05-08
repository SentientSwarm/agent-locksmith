//! T6.5 — MtlsAuthenticator (verification gate).

use agent_locksmith::migrations::open_and_migrate;
use agent_locksmith::mtls::{MtlsAuthenticator, MtlsValidator};
use agent_locksmith::repo::AgentRepository;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, KeyUsagePurpose,
};
use std::sync::Arc;
use tempfile::TempDir;

struct TestCa {
    pem: String,
    key: KeyPair,
    cert: rcgen::Certificate,
}

fn mint_ca() -> TestCa {
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "test-mtls-auth-ca");
    params.distinguished_name = dn;
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let key = KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();
    TestCa {
        pem: cert.pem(),
        key,
        cert,
    }
}

fn mint_leaf(ca: &TestCa, cn: &str) -> Vec<u8> {
    let mut params = CertificateParams::new(vec![format!("{cn}.local")]).unwrap();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, cn);
    params.distinguished_name = dn;
    let key = KeyPair::generate().unwrap();
    params
        .signed_by(&key, &ca.cert, &ca.key)
        .unwrap()
        .der()
        .to_vec()
}

async fn fixture() -> (TempDir, AgentRepository) {
    let dir = TempDir::new().unwrap();
    let pool = open_and_migrate(&dir.path().join("locksmith.db"))
        .await
        .unwrap();
    (dir, AgentRepository::new(pool))
}

async fn create_agent_with_cert_identity(
    repo: &AgentRepository,
    name: &str,
    cert_identity: &str,
) -> String {
    let (public_id, _secret) = repo
        .create(name, None, None, None, None, None)
        .await
        .unwrap();
    repo.set_cert_identity(&public_id, Some(cert_identity))
        .await
        .unwrap();
    public_id
}

#[tokio::test]
async fn authenticate_cert_resolves_known_identity() {
    let ca = mint_ca();
    let leaf = mint_leaf(&ca, "agent-7");

    let (_dir, repo) = fixture().await;
    let public_id = create_agent_with_cert_identity(&repo, "agent-7", "agent-7").await;

    let validator = Arc::new(MtlsValidator::new(&ca.pem).unwrap());
    let authn = MtlsAuthenticator::new(validator, repo);
    let identity = authn.authenticate_cert(&leaf).await.expect("auth ok");
    assert_eq!(identity.public_id, public_id);
    assert_eq!(identity.name, "agent-7");
}

#[tokio::test]
async fn authenticate_cert_rejects_unknown_identity() {
    let ca = mint_ca();
    let leaf = mint_leaf(&ca, "ghost");

    let (_dir, repo) = fixture().await;
    // Note: no agent with cert_identity="ghost" in the DB.
    let validator = Arc::new(MtlsValidator::new(&ca.pem).unwrap());
    let authn = MtlsAuthenticator::new(validator, repo);
    let err = authn.authenticate_cert(&leaf).await.unwrap_err();
    assert_eq!(err.code(), "invalid_credential");
}

#[tokio::test]
async fn authenticate_cert_rejects_chain_against_unrelated_ca() {
    let ca_a = mint_ca();
    let ca_b = mint_ca();
    let leaf = mint_leaf(&ca_a, "agent-7");

    let (_dir, repo) = fixture().await;
    create_agent_with_cert_identity(&repo, "agent-7", "agent-7").await;

    // Validator trusts ca_b only; leaf was issued by ca_a.
    let validator = Arc::new(MtlsValidator::new(&ca_b.pem).unwrap());
    let authn = MtlsAuthenticator::new(validator, repo);
    let err = authn.authenticate_cert(&leaf).await.unwrap_err();
    assert_eq!(err.code(), "invalid_credential");
}

#[tokio::test]
async fn authenticate_cert_rejects_revoked_agent() {
    let ca = mint_ca();
    let leaf = mint_leaf(&ca, "agent-revoked");

    let (_dir, repo) = fixture().await;
    let public_id = create_agent_with_cert_identity(&repo, "agent-revoked", "agent-revoked").await;
    repo.revoke(&public_id).await.unwrap();

    let validator = Arc::new(MtlsValidator::new(&ca.pem).unwrap());
    let authn = MtlsAuthenticator::new(validator, repo);
    let err = authn.authenticate_cert(&leaf).await.unwrap_err();
    assert_eq!(err.code(), "invalid_credential");
}
