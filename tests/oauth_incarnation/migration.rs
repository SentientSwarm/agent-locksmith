use super::support::*;
use sqlx::{Connection, Row};

async fn prior_database(path: &std::path::Path) -> Result<sqlx::SqliteConnection, Error> {
    let opts = sqlx::sqlite::SqliteConnectOptions::new()
        .filename(path)
        .create_if_missing(true)
        .foreign_keys(true);
    let mut conn = sqlx::SqliteConnection::connect_with(&opts).await?;
    let mut old = sqlx::migrate!();
    old.migrations = old
        .iter()
        .filter(|m| m.version <= 9)
        .cloned()
        .collect::<Vec<_>>()
        .into();
    old.run(&mut conn).await?;
    Ok(conn)
}

#[tokio::test]
async fn migration_preserves_sealed_rows_and_prior_binary_guard() -> Result<(), Error> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("state.db");
    let mut conn = prior_database(&path).await?;
    let key = SealingKey::generate()?;
    seed_old(&mut conn, &key).await?;
    let before = stored_columns(&mut conn).await?;
    conn.close().await?;
    let db = pool(&dir).await;
    let after = stored_columns(&mut *db.acquire().await?).await?;
    assert_eq!(before, after);
    let repo = OauthSessionRepository::new(db.clone());
    let row = current(&repo, &key).await;
    assert_pair(&row, "access", "refresh");
    assert!(row.incarnation > 0 && row.degraded);
    assert_eq!(row.token_version, 0);
    let mut old = sqlx::migrate!();
    old.migrations = old
        .iter()
        .filter(|m| m.version <= 9)
        .cloned()
        .collect::<Vec<_>>()
        .into();
    assert!(matches!(
        old.run(&db).await,
        Err(sqlx::migrate::MigrateError::VersionMissing(10))
    ));
    Ok(())
}

async fn seed_old(conn: &mut sqlx::SqliteConnection, key: &SealingKey) -> Result<(), Error> {
    let (refresh, rn) = key.seal(b"refresh")?;
    let (access, an) = key.seal(b"access")?;
    sqlx::query("INSERT INTO oauth_sessions VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
        .bind("fixture")
        .bind("reader")
        .bind(refresh)
        .bind(rn)
        .bind(access)
        .bind(an)
        .bind(7200)
        .bind("read scope")
        .bind(1)
        .bind(12)
        .bind(34)
        .bind("account")
        .execute(conn)
        .await?;
    Ok(())
}

async fn stored_columns(conn: &mut sqlx::SqliteConnection) -> Result<String, Error> {
    let row = sqlx::query(
        "SELECT json_array(name, session_label,
        hex(refresh_token_ciphertext), hex(refresh_token_nonce),
        hex(access_token_ciphertext), hex(access_token_nonce), access_token_expires_at,
        scope, degraded, created_at, updated_at, account_id) AS record FROM oauth_sessions",
    )
    .fetch_one(conn)
    .await?;
    Ok(row.try_get("record")?)
}
