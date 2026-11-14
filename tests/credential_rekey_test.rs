//! Offline re-key of the stored-credential store: every sealed value moves
//! from one credential sealing key to another in one transaction, or none
//! does. Used to rotate the key and to give a database copy its own key.

use agent_locksmith::migrations::open_and_migrate;
use agent_locksmith::repo::credential_secrets::CredentialSecretsRepository;
use agent_locksmith::secret::CredentialSealingKey;
use agent_locksmith::secret::rekey::{RekeyError, rekey_credentials};
use tempfile::TempDir;

async fn store(dir: &TempDir, key: &CredentialSealingKey, values: &[&str]) -> Vec<String> {
    let pool = open_and_migrate(&dir.path().join("locksmith.db"))
        .await
        .unwrap();
    let repo = CredentialSecretsRepository::new(pool.clone());
    let mut refs = Vec::new();
    for value in values {
        let (ct, nonce) = key.seal(value.as_bytes()).unwrap();
        refs.push(repo.insert(&ct, &nonce).await.unwrap());
    }
    repo.tombstone(&refs[0]).await.unwrap();
    pool.close().await;
    refs
}

async fn unseal_all(dir: &TempDir, key: &CredentialSealingKey) -> Vec<Result<String, ()>> {
    let pool = open_and_migrate(&dir.path().join("locksmith.db"))
        .await
        .unwrap();
    let rows: Vec<(Vec<u8>, Vec<u8>)> =
        sqlx::query_as("SELECT sealed_value, nonce FROM credential_secrets ORDER BY rowid")
            .fetch_all(&pool)
            .await
            .unwrap();
    pool.close().await;
    rows.iter()
        .map(|(ct, nonce)| {
            key.unseal(ct, nonce)
                .map(|p| String::from_utf8(p).unwrap())
                .map_err(|_| ())
        })
        .collect()
}

#[tokio::test]
async fn every_value_moves_to_the_new_key() {
    let dir = TempDir::new().unwrap();
    let (old, new) = (
        CredentialSealingKey::generate().unwrap(),
        CredentialSealingKey::generate().unwrap(),
    );
    store(&dir, &old, &["tombstoned-value", "live-a", "live-b"]).await;

    let count = rekey_credentials(&dir.path().join("locksmith.db"), &old, &new)
        .await
        .unwrap();

    assert_eq!(count, 3, "tombstoned rows are re-keyed too");
    let plain: Vec<_> = unseal_all(&dir, &new).await;
    assert_eq!(
        plain,
        vec![
            Ok("tombstoned-value".into()),
            Ok("live-a".into()),
            Ok("live-b".into())
        ]
    );
    assert!(unseal_all(&dir, &old).await.iter().all(Result::is_err));
}

#[tokio::test]
async fn a_wrong_old_key_changes_nothing() {
    let dir = TempDir::new().unwrap();
    let (old, other, new) = (
        CredentialSealingKey::generate().unwrap(),
        CredentialSealingKey::generate().unwrap(),
        CredentialSealingKey::generate().unwrap(),
    );
    store(&dir, &old, &["a", "b"]).await;

    let err = rekey_credentials(&dir.path().join("locksmith.db"), &other, &new)
        .await
        .unwrap_err();

    assert!(matches!(err, RekeyError::WrongKey), "{err:?}");
    assert!(unseal_all(&dir, &old).await.iter().all(Result::is_ok));
}

#[tokio::test]
async fn a_missing_database_is_not_created() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("absent.db");
    let key = CredentialSealingKey::generate().unwrap();
    assert!(rekey_credentials(&path, &key, &key).await.is_err());
    assert!(!path.exists());
}

fn key_file(dir: &TempDir, name: &str, key_b64: &str, mode: u32) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let path = dir.path().join(name);
    std::fs::write(&path, format!("{key_b64}\n")).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
    path
}

fn cli(db: &std::path::Path, old: &std::path::Path, new: &std::path::Path) -> std::process::Output {
    std::process::Command::new(env!("CARGO_BIN_EXE_locksmith"))
        .arg("rekey-credentials")
        .arg("--database")
        .arg(db)
        .arg("--old-key-file")
        .arg(old)
        .arg("--new-key-file")
        .arg(new)
        .output()
        .unwrap()
}

#[tokio::test]
async fn the_cli_reads_keys_from_files_and_reports_the_count() {
    let dir = TempDir::new().unwrap();
    let (old_b64, new_b64) = (fresh_b64(), fresh_b64());
    let old = CredentialSealingKey::from_b64(&old_b64).unwrap();
    store(&dir, &old, &["t", "a"]).await;
    let out = cli(
        &dir.path().join("locksmith.db"),
        &key_file(&dir, "old.key", &old_b64, 0o600),
        &key_file(&dir, "new.key", &new_b64, 0o400),
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        r#"{"rekeyed":2}"#
    );
    let new = CredentialSealingKey::from_b64(&new_b64).unwrap();
    assert!(unseal_all(&dir, &new).await.iter().all(Result::is_ok));
}

#[tokio::test]
async fn the_cli_refuses_a_key_file_others_can_read() {
    let dir = TempDir::new().unwrap();
    let (old_b64, new_b64) = (fresh_b64(), fresh_b64());
    let old = CredentialSealingKey::from_b64(&old_b64).unwrap();
    store(&dir, &old, &["t"]).await;
    let out = cli(
        &dir.path().join("locksmith.db"),
        &key_file(&dir, "old.key", &old_b64, 0o644),
        &key_file(&dir, "new.key", &new_b64, 0o600),
    );
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("old.key"), "{stderr}");
    assert!(!stderr.contains(&old_b64) && !stderr.contains(&new_b64));
    assert!(unseal_all(&dir, &old).await.iter().all(Result::is_ok));
}

#[tokio::test]
async fn the_cli_exits_nonzero_on_a_wrong_old_key() {
    let dir = TempDir::new().unwrap();
    let old = CredentialSealingKey::from_b64(&fresh_b64()).unwrap();
    store(&dir, &old, &["t"]).await;
    let out = cli(
        &dir.path().join("locksmith.db"),
        &key_file(&dir, "old.key", &fresh_b64(), 0o600),
        &key_file(&dir, "new.key", &fresh_b64(), 0o600),
    );
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("does not open"));
}

fn fresh_b64() -> String {
    use base64::Engine;
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).unwrap();
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

#[tokio::test]
async fn a_late_unopenable_row_rolls_back_rows_already_rewritten() {
    let dir = TempDir::new().unwrap();
    let (old, other, new) = (
        CredentialSealingKey::generate().unwrap(),
        CredentialSealingKey::generate().unwrap(),
        CredentialSealingKey::generate().unwrap(),
    );
    store(&dir, &old, &["a", "b"]).await;
    store(&dir, &other, &["stray"]).await;

    let err = rekey_credentials(&dir.path().join("locksmith.db"), &old, &new)
        .await
        .unwrap_err();

    assert!(matches!(err, RekeyError::WrongKey), "{err:?}");
    let under_old = unseal_all(&dir, &old).await;
    assert!(
        under_old[0].is_ok() && under_old[1].is_ok(),
        "{under_old:?}"
    );
}

#[tokio::test]
async fn the_database_file_alone_carries_the_new_key() {
    let dir = TempDir::new().unwrap();
    let (old, new) = (
        CredentialSealingKey::generate().unwrap(),
        CredentialSealingKey::generate().unwrap(),
    );
    store(&dir, &old, &["a"]).await;
    rekey_credentials(&dir.path().join("locksmith.db"), &old, &new)
        .await
        .unwrap();

    let copy = TempDir::new().unwrap();
    std::fs::copy(
        dir.path().join("locksmith.db"),
        copy.path().join("locksmith.db"),
    )
    .unwrap();
    assert_eq!(unseal_all(&copy, &new).await, vec![Ok("a".to_string())]);
}

#[tokio::test]
async fn the_same_key_twice_is_refused() {
    let dir = TempDir::new().unwrap();
    let b64 = fresh_b64();
    let key = CredentialSealingKey::from_b64(&b64).unwrap();
    store(&dir, &key, &["a"]).await;
    let out = cli(
        &dir.path().join("locksmith.db"),
        &key_file(&dir, "old.key", &b64, 0o600),
        &key_file(&dir, "new.key", &b64, 0o600),
    );
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("same key"));
}
