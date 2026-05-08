//! T5.1 — FileSealedBackend reads chmod-restricted decrypted file.
//!
//! systemd-creds (or an operator script) writes the decrypted credential
//! to a permission-restricted path; the backend verifies the path is
//! not group/world readable, reads the bytes, and caches the result.

use agent_locksmith::secret::{BackendError, FileSealedBackend, SecretBackend, SecretRef};
use secrecy::ExposeSecret;
use std::os::unix::fs::PermissionsExt;
use tempfile::TempDir;

#[tokio::test]
async fn file_sealed_happy_path_reads_and_strips_trailing_newline() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("api_key");
    std::fs::write(&path, "shhh\n").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

    let backend = FileSealedBackend::new();
    let resolved = backend
        .resolve(&SecretRef::FromFileSealed { path: path.clone() })
        .await
        .expect("resolve ok");
    assert_eq!(resolved.expose_secret(), "shhh");
}

#[tokio::test]
async fn file_sealed_missing_file_errors() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("absent");
    let backend = FileSealedBackend::new();
    let err = backend
        .resolve(&SecretRef::FromFileSealed { path })
        .await
        .unwrap_err();
    matches!(err, BackendError::Io(_));
}

#[tokio::test]
async fn file_sealed_rejects_world_readable_file() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("loose");
    std::fs::write(&path, "shhh").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

    let backend = FileSealedBackend::new();
    let err = backend
        .resolve(&SecretRef::FromFileSealed { path: path.clone() })
        .await
        .unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("group") || msg.contains("world"),
        "error names the perm problem; got: {msg}"
    );
    assert!(msg.contains(path.to_str().unwrap()));
}

#[tokio::test]
async fn file_sealed_caches_after_first_read() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("cached");
    std::fs::write(&path, "v1").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

    let backend = FileSealedBackend::new();
    let first = backend
        .resolve(&SecretRef::FromFileSealed { path: path.clone() })
        .await
        .unwrap();
    assert_eq!(first.expose_secret(), "v1");

    // Mutate disk; cache should still return the original value.
    std::fs::write(&path, "v2").unwrap();
    let second = backend
        .resolve(&SecretRef::FromFileSealed { path: path.clone() })
        .await
        .unwrap();
    assert_eq!(
        second.expose_secret(),
        "v1",
        "cache must short-circuit disk reads after first resolve"
    );
}

#[tokio::test]
async fn file_sealed_rejects_non_file_sealed_variant() {
    let backend = FileSealedBackend::new();
    let err = backend
        .resolve(&SecretRef::FromEnv {
            var: "X".into(),
            prefix: None,
        })
        .await
        .unwrap_err();
    assert!(matches!(err, BackendError::NotImplemented(_)));
}
