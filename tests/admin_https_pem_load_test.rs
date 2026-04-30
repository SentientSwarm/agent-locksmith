//! T4.2 — TLS cert/key PEM load is fail-fast.
//!
//! Asserts the contract of `admin::https::load_tls_config`:
//! - missing file → `InvalidData`
//! - malformed PEM → `InvalidData`
//! - valid cert+key → success
//!
//! These are the boundary cases that the daemon will surface as
//! `DaemonError::Server` at startup. Pinning them at this layer keeps
//! the integration test focused on the listener-binding contract.

use agent_locksmith::admin::https::load_tls_config;
use rcgen::KeyPair;
use tempfile::TempDir;

fn mint_pem_pair() -> (String, String) {
    let params = rcgen::CertificateParams::new(vec!["127.0.0.1".to_string()]).unwrap();
    let key = KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();
    (cert.pem(), key.serialize_pem())
}

#[tokio::test]
async fn load_tls_config_missing_cert_file_fails_fast() {
    let dir = TempDir::new().unwrap();
    let cert = dir.path().join("absent.crt");
    let key = dir.path().join("server.key");
    let (_, key_pem) = mint_pem_pair();
    std::fs::write(&key, key_pem).unwrap();

    let err = load_tls_config(&cert, &key).await.unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    let msg = err.to_string();
    assert!(
        msg.contains("absent.crt"),
        "error names the offending path; got: {msg}"
    );
}

#[tokio::test]
async fn load_tls_config_missing_key_file_fails_fast() {
    let dir = TempDir::new().unwrap();
    let cert = dir.path().join("server.crt");
    let key = dir.path().join("absent.key");
    let (cert_pem, _) = mint_pem_pair();
    std::fs::write(&cert, cert_pem).unwrap();

    let err = load_tls_config(&cert, &key).await.unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    assert!(err.to_string().contains("absent.key"));
}

#[tokio::test]
async fn load_tls_config_malformed_pem_fails_fast() {
    let dir = TempDir::new().unwrap();
    let cert = dir.path().join("garbage.crt");
    let key = dir.path().join("server.key");
    std::fs::write(&cert, b"this is not a PEM cert chain\n").unwrap();
    let (_, key_pem) = mint_pem_pair();
    std::fs::write(&key, key_pem).unwrap();

    let err = load_tls_config(&cert, &key).await.unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
}

#[tokio::test]
async fn load_tls_config_valid_pem_succeeds() {
    let dir = TempDir::new().unwrap();
    let cert = dir.path().join("server.crt");
    let key = dir.path().join("server.key");
    let (cert_pem, key_pem) = mint_pem_pair();
    std::fs::write(&cert, cert_pem).unwrap();
    std::fs::write(&key, key_pem).unwrap();

    let result = load_tls_config(&cert, &key).await;
    assert!(result.is_ok(), "valid PEM must load: {result:?}");
}
