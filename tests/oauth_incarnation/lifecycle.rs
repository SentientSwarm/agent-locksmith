use super::support::*;

#[tokio::test]
async fn concurrent_snapshots_have_one_committed_winner() -> Result<(), Error> {
    let (_dir, repo, key) = fixture().await?;
    let old = seed(&repo, &key, "old").await?;
    let (a, b) = tokio::join!(
        repo.update_tokens(&key, &old, "A", 7200, Some("refresh-A")),
        repo.update_tokens(&key, &old, "B", 7200, Some("refresh-B"))
    );
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
    let winner = a.or(b)?;
    assert_eq!(winner.incarnation, old.incarnation);
    assert_eq!(winner.token_version, old.token_version + 1);
    let stored = current(&repo, &key).await;
    assert_pair(
        &stored,
        winner.access_token.as_ref().unwrap().expose_secret(),
        winner.refresh_token.expose_secret(),
    );
    stale(repo.mark_degraded(&old).await);
    stale(repo.delete_if_current(&old).await);
    assert!(!current(&repo, &key).await.degraded);
    Ok(())
}

#[tokio::test]
async fn stale_bootstrap_cleanup_does_not_delete_replacement() -> Result<(), Error> {
    let (_dir, repo, key) = fixture().await?;
    let old = seed(&repo, &key, "old").await?;
    repo.delete("fixture", "reader").await?;
    let new = seed(&repo, &key, "new").await?;
    assert!(new.incarnation > old.incarnation);
    stale(repo.delete_if_current(&old).await);
    repo.delete_if_current(&new).await?;
    assert!(repo.get(&key, "fixture", "reader").await?.is_none());
    Ok(())
}

#[tokio::test]
async fn recreate_and_restart_do_not_reuse_committed_identity() -> Result<(), Error> {
    let (dir, repo, key) = fixture().await?;
    let old = seed(&repo, &key, "old").await?;
    repo.delete("fixture", "reader").await?;
    let reopened = OauthSessionRepository::new(pool(&dir).await);
    let new = seed(&reopened, &key, "new").await?;
    // Force the same display timestamp to prove it is not the persistence identity.
    sqlx::query("UPDATE oauth_sessions SET created_at = ?")
        .bind(old.created_at)
        .execute(&pool(&dir).await)
        .await?;
    assert!(new.incarnation > old.incarnation);
    assert_eq!(current(&reopened, &key).await.created_at, old.created_at);
    assert!(
        repo.update_tokens(&key, &old, "late", 7200, None)
            .await
            .is_err()
    );
    assert_pair(&current(&reopened, &key).await, "new", "new");
    Ok(())
}

#[tokio::test]
async fn degradation_advances_version_and_omitted_refresh_stays_coherent() -> Result<(), Error> {
    let (_dir, repo, key) = fixture().await?;
    let old = seed(&repo, &key, "old").await?;
    repo.mark_degraded(&old).await?;
    assert!(
        repo.update_tokens(&key, &old, "late", 7200, None)
            .await
            .is_err()
    );
    let degraded = current(&repo, &key).await;
    assert_eq!(degraded.token_version, old.token_version + 1);
    let new = repo
        .update_tokens(&key, &degraded, "new", 7200, None)
        .await?;
    assert_pair(&new, "new", "old");
    assert!(!new.degraded);
    assert_eq!(new.token_version, old.token_version + 2);
    assert_eq!(new.access_token_expires_at, Some(7200));
    Ok(())
}

#[tokio::test]
async fn version_overflow_cannot_wrap_or_coerce_to_real() -> Result<(), Error> {
    let (dir, repo, key) = fixture().await?;
    seed(&repo, &key, "old").await?;
    sqlx::query("UPDATE oauth_sessions SET token_version = 9223372036854775807")
        .execute(&pool(&dir).await)
        .await?;
    let last = current(&repo, &key).await;
    assert!(
        repo.update_tokens(&key, &last, "new", 7200, None)
            .await
            .is_err()
    );
    stale(repo.mark_degraded(&last).await);
    assert_pair(&current(&repo, &key).await, "old", "old");
    assert!(repo.delete("fixture", "reader").await?);
    Ok(())
}
