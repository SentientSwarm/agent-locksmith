use super::support::*;

async fn reject_commit(pool: &sqlx::SqlitePool, event: &str) -> Result<(), Error> {
    sqlx::raw_sql(
        "CREATE TABLE parent (id INTEGER PRIMARY KEY);
        CREATE TABLE fault (id INTEGER REFERENCES parent(id) DEFERRABLE INITIALLY DEFERRED);",
    )
    .execute(pool)
    .await?;
    // RETURNING can succeed; the deferred constraint fails only when COMMIT runs.
    let sql = format!(
        "CREATE TRIGGER reject_commit AFTER {event} ON oauth_sessions
        BEGIN INSERT INTO fault VALUES(1); END;"
    );
    sqlx::query(&sql).execute(pool).await?;
    Ok(())
}

#[tokio::test]
async fn token_commit_failure_returns_no_credentials_and_rolls_back_pair() -> Result<(), Error> {
    let (dir, repo, key) = fixture().await?;
    let old = seed(&repo, &key, "old").await?;
    reject_commit(&pool(&dir).await, "UPDATE").await?;
    assert!(
        repo.update_tokens(&key, &old, "new", 7200, Some("rotated"))
            .await
            .is_err()
    );
    let stored = current(&repo, &key).await;
    assert_pair(&stored, "old", "old");
    assert_eq!(stored.token_version, old.token_version);
    Ok(())
}

#[tokio::test]
async fn bootstrap_commit_failure_returns_no_snapshot() -> Result<(), Error> {
    let (dir, repo, key) = fixture().await?;
    reject_commit(&pool(&dir).await, "INSERT").await?;
    assert!(seed(&repo, &key, "uncommitted").await.is_err());
    assert!(repo.get(&key, "fixture", "reader").await?.is_none());
    Ok(())
}

#[tokio::test]
async fn failed_decode_does_not_commit_provider_access_token() -> Result<(), Error> {
    let (dir, repo, key) = fixture().await?;
    let old = seed(&repo, &key, "old").await?;
    let db = pool(&dir).await;
    sqlx::query("UPDATE oauth_sessions SET refresh_token_ciphertext = X'00'")
        .execute(&db)
        .await?;
    assert!(
        repo.update_tokens(&key, &old, "new", 7200, None)
            .await
            .is_err()
    );
    let version: i64 = sqlx::query_scalar("SELECT token_version FROM oauth_sessions")
        .fetch_one(&db)
        .await?;
    assert_eq!(version, old.token_version);
    Ok(())
}

#[tokio::test]
async fn sql_write_failure_cannot_return_uncommitted_tokens() -> Result<(), Error> {
    let (dir, repo, key) = fixture().await?;
    let old = seed(&repo, &key, "old").await?;
    sqlx::query(
        "CREATE TRIGGER reject_write BEFORE UPDATE ON oauth_sessions
        BEGIN SELECT RAISE(ABORT, 'synthetic failure'); END;",
    )
    .execute(&pool(&dir).await)
    .await?;
    assert!(
        repo.update_tokens(&key, &old, "new", 7200, Some("rotated"))
            .await
            .is_err()
    );
    assert_pair(&current(&repo, &key).await, "old", "old");
    Ok(())
}
