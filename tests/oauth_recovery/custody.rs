use super::support::*;
use secrecy::ExposeSecret;

async fn fixture() -> (sqlx::SqlitePool, OauthSessionRepository, SealingKey) {
    let pool = migrations::open_and_migrate(std::path::Path::new(":memory:"))
        .await
        .unwrap();
    let repo = OauthSessionRepository::new(pool.clone());
    (pool, repo, SealingKey::generate().unwrap())
}

async fn current(
    repo: &OauthSessionRepository,
    key: &SealingKey,
) -> agent_locksmith::oauth::OauthSession {
    repo.get(key, "fixture", "reader").await.unwrap().unwrap()
}

#[tokio::test]
async fn committed_claim_is_unique_and_only_attempt_can_publish() {
    let (_db, repo, key) = fixture().await;
    let old = seed(&repo, &key).await;
    let attempt = repo.begin_refresh(&key, &old).await.unwrap();
    let pending = current(&repo, &key).await;
    assert!(pending.refresh_pending);
    assert_eq!(pending.token_version, old.token_version + 1);
    assert!(repo.begin_refresh(&key, &old).await.is_err());
    assert!(repo.begin_refresh(&key, &pending).await.is_err());
    assert!(
        repo.update_tokens(&key, &pending, "forbidden", 42, None)
            .await
            .is_err()
    );
    assert!(repo.mark_degraded(&pending).await.is_err());
    assert!(repo.delete_if_current(&pending).await.is_err());
    let done = repo
        .complete_refresh(&key, &attempt, "new-access", 42, Some("new-refresh"))
        .await
        .unwrap();
    published(done, old.token_version);
    assert!(
        repo.complete_refresh(&key, &attempt, "replay", 42, None)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn old_attempt_cannot_replace_reconnected_account() {
    let (_db, repo, key) = fixture().await;
    let old = seed(&repo, &key).await;
    let attempt = repo.begin_refresh(&key, &old).await.unwrap();
    repo.delete("fixture", "reader").await.unwrap();
    let fresh = seed(&repo, &key).await;
    assert!(fresh.incarnation > old.incarnation);
    assert!(
        repo.complete_refresh(&key, &attempt, "late", 42, Some("late"))
            .await
            .is_err()
    );
    assert!(repo.mark_degraded(attempt.session()).await.is_err());
    assert!(repo.delete_if_current(attempt.session()).await.is_err());
    let row = current(&repo, &key).await;
    assert_eq!(row.incarnation, fresh.incarnation);
    assert!(!row.refresh_pending);
}

#[tokio::test]
async fn exhausted_or_degraded_rows_cannot_claim() {
    let (db, repo, key) = fixture().await;
    seed(&repo, &key).await;
    for version in [i64::MAX - 1, i64::MAX] {
        sqlx::query("UPDATE oauth_sessions SET token_version=?")
            .bind(version)
            .execute(&db)
            .await
            .unwrap();
        assert!(
            repo.begin_refresh(&key, &current(&repo, &key).await)
                .await
                .is_err()
        );
        assert!(!current(&repo, &key).await.refresh_pending);
    }
    sqlx::query("UPDATE oauth_sessions SET token_version=0, degraded=1")
        .execute(&db)
        .await
        .unwrap();
    assert!(
        repo.begin_refresh(&key, &current(&repo, &key).await)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn pending_does_not_hold_database_write_lock_or_affect_other_account() {
    let (db, repo, key) = fixture().await;
    let old = seed(&repo, &key).await;
    let _attempt = repo.begin_refresh(&key, &old).await.unwrap();
    let other = repo
        .create(
            &key,
            "other",
            "reader",
            "other-refresh",
            Some("other-access"),
            Some(1),
            "",
        )
        .await
        .unwrap();
    assert!(!other.refresh_pending);
    assert_eq!(
        repo.list_pending_refresh(i64::MAX).await.unwrap(),
        vec![("other".into(), "reader".into())]
    );
    sqlx::query("CREATE TABLE unrelated(id INTEGER)")
        .execute(&db)
        .await
        .unwrap();
}

#[tokio::test]
async fn omitted_refresh_preserves_claimed_pair_and_scope() {
    let (_db, repo, key) = fixture().await;
    let old = seed(&repo, &key).await;
    let attempt = repo.begin_refresh(&key, &old).await.unwrap();
    let done = repo
        .complete_refresh(&key, &attempt, "new", 9000, None)
        .await
        .unwrap();
    assert_eq!(
        done.refresh_token.expose_secret(),
        old.refresh_token.expose_secret()
    );
    assert_eq!(done.scope, old.scope);
}

fn published(done: agent_locksmith::oauth::OauthSession, old_version: i64) {
    assert!(!done.refresh_pending);
    assert!(!done.degraded);
    assert_eq!(done.token_version, old_version + 2);
    assert_eq!(done.access_token.unwrap().expose_secret(), "new-access");
    assert_eq!(done.refresh_token.expose_secret(), "new-refresh");
}
