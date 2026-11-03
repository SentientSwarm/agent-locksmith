use super::*;

#[tokio::test]
async fn create_and_get_roundtrip() {
    let (_dir, repo, key) = fresh_repo().await;
    let session = repo
        .create(
            &key,
            "codex",
            DEF,
            "refresh-token-abc",
            Some("access-token-xyz"),
            Some(unix_now() + 3600),
            "openai-api",
        )
        .await
        .unwrap();
    assert_eq!(session.name, "codex");
    assert_eq!(session.session_label, DEF);
    assert_eq!(session.refresh_token.expose_secret(), "refresh-token-abc");
    assert_eq!(
        session.access_token.as_ref().unwrap().expose_secret(),
        "access-token-xyz"
    );

    assert_roundtrip(&repo.get(&key, "codex", DEF).await.unwrap().unwrap());
}

fn assert_roundtrip(back: &OauthSession) {
    assert_eq!(back.refresh_token.expose_secret(), "refresh-token-abc");
    assert_eq!(
        back.access_token.as_ref().unwrap().expose_secret(),
        "access-token-xyz"
    );
    assert_eq!(back.scope, "openai-api");
    assert!(!back.degraded);
}

#[tokio::test]
async fn update_tokens_replaces_access_only() {
    let (_dir, repo, key) = fresh_repo().await;
    repo.create(&key, "x", DEF, "refresh-1", Some("access-1"), Some(100), "")
        .await
        .unwrap();
    repo.update_tokens(
        &key,
        &repo.get(&key, "x", DEF).await.unwrap().unwrap(),
        "access-2",
        200,
        None,
    )
    .await
    .unwrap();
    let s = repo.get(&key, "x", DEF).await.unwrap().unwrap();
    assert_eq!(s.refresh_token.expose_secret(), "refresh-1"); // unchanged
    assert_eq!(s.access_token.as_ref().unwrap().expose_secret(), "access-2");
    assert_eq!(s.access_token_expires_at, Some(200));
}

#[tokio::test]
async fn update_tokens_replaces_both_when_refresh_supplied() {
    let (_dir, repo, key) = fresh_repo().await;
    repo.create(&key, "x", DEF, "refresh-1", Some("access-1"), Some(100), "")
        .await
        .unwrap();
    repo.update_tokens(
        &key,
        &repo.get(&key, "x", DEF).await.unwrap().unwrap(),
        "access-2",
        200,
        Some("refresh-2"),
    )
    .await
    .unwrap();
    let s = repo.get(&key, "x", DEF).await.unwrap().unwrap();
    assert_eq!(s.refresh_token.expose_secret(), "refresh-2");
    assert_eq!(s.access_token.as_ref().unwrap().expose_secret(), "access-2");
}

#[tokio::test]
async fn mark_degraded_clears_on_update() {
    let (_dir, repo, key) = fresh_repo().await;
    repo.create(&key, "x", DEF, "rt", Some("at"), Some(100), "")
        .await
        .unwrap();
    repo.mark_degraded(&repo.get(&key, "x", DEF).await.unwrap().unwrap())
        .await
        .unwrap();
    assert!(repo.get(&key, "x", DEF).await.unwrap().unwrap().degraded);

    // Successful refresh clears degraded flag (per ADR-0005 D6).
    repo.update_tokens(
        &key,
        &repo.get(&key, "x", DEF).await.unwrap().unwrap(),
        "at-2",
        200,
        None,
    )
    .await
    .unwrap();
    assert!(!repo.get(&key, "x", DEF).await.unwrap().unwrap().degraded);
}

#[tokio::test]
async fn list_pending_refresh_filters_degraded() {
    let (_dir, repo, key) = fresh_repo().await;
    let now = unix_now();
    repo.create(&key, "due", DEF, "rt", Some("at"), Some(now), "")
        .await
        .unwrap();
    repo.create(&key, "future", DEF, "rt", Some("at"), Some(now + 3600), "")
        .await
        .unwrap();
    repo.create(&key, "degraded", DEF, "rt", Some("at"), Some(now), "")
        .await
        .unwrap();
    repo.mark_degraded(&repo.get(&key, "degraded", DEF).await.unwrap().unwrap())
        .await
        .unwrap();

    // Threshold = now + 60 → "due" is pending; "future" not yet;
    // "degraded" is filtered out even though it's expired.
    let pending = repo.list_pending_refresh(now + 60).await.unwrap();
    assert_eq!(pending, vec![("due".to_string(), DEF.to_string())]);
}

#[tokio::test]
async fn audit_session_id_is_stable_for_same_session() {
    let (_dir, repo, key) = fresh_repo().await;
    let s1 = repo
        .create(&key, "x", DEF, "rt", Some("at"), Some(100), "")
        .await
        .unwrap();
    let id1 = s1.audit_session_id();
    // Reload — should get the same audit ID.
    let s2 = repo.get(&key, "x", DEF).await.unwrap().unwrap();
    assert_eq!(id1, s2.audit_session_id());
    assert_eq!(id1.len(), 16); // 8 bytes → 16 hex chars
}

#[tokio::test]
async fn delete_clears_session() {
    let (_dir, repo, key) = fresh_repo().await;
    repo.create(&key, "x", DEF, "rt", Some("at"), Some(100), "")
        .await
        .unwrap();
    assert!(repo.delete("x", DEF).await.unwrap());
    assert!(repo.get(&key, "x", DEF).await.unwrap().is_none());
    assert!(!repo.delete("x", DEF).await.unwrap()); // idempotent
}

#[tokio::test]
async fn unseal_with_wrong_key_returns_sealing_error() {
    let (_dir, repo, key1) = fresh_repo().await;
    repo.create(&key1, "x", DEF, "rt", Some("at"), Some(100), "")
        .await
        .unwrap();
    let key2 = SealingKey::generate().unwrap();
    let err = repo.get(&key2, "x", DEF).await.unwrap_err();
    assert!(matches!(err, OauthSessionError::Sealing(_)));
}
