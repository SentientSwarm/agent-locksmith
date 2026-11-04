use super::*;

#[tokio::test]
async fn two_labels_under_same_name_coexist() {
    let (_dir, repo, key) = fresh_repo().await;
    repo.create(&key, "codex", "hermes", "rt-h", Some("at-h"), Some(100), "")
        .await
        .unwrap();
    repo.create(
        &key,
        "codex",
        "openclaw",
        "rt-o",
        Some("at-o"),
        Some(200),
        "",
    )
    .await
    .unwrap();

    let h = repo.get(&key, "codex", "hermes").await.unwrap().unwrap();
    let o = repo.get(&key, "codex", "openclaw").await.unwrap().unwrap();
    assert_eq!(h.refresh_token.expose_secret(), "rt-h");
    assert_eq!(o.refresh_token.expose_secret(), "rt-o");
    // Audit IDs are distinct because session_label is part of the
    // hash input.
    assert_ne!(h.audit_session_id(), o.audit_session_id());
}

#[tokio::test]
async fn get_with_wrong_label_returns_none() {
    let (_dir, repo, key) = fresh_repo().await;
    repo.create(&key, "codex", "hermes", "rt", Some("at"), Some(100), "")
        .await
        .unwrap();
    // Asking for the same name under a label we never created
    // returns None rather than spilling the wrong label's session.
    assert!(repo.get(&key, "codex", "openclaw").await.unwrap().is_none());
    assert!(repo.get(&key, "codex", DEF).await.unwrap().is_none());
}

#[tokio::test]
async fn delete_one_label_leaves_other_intact() {
    let (_dir, repo, key) = fresh_repo().await;
    repo.create(&key, "codex", "hermes", "rt", Some("at"), Some(100), "")
        .await
        .unwrap();
    repo.create(&key, "codex", "openclaw", "rt", Some("at"), Some(100), "")
        .await
        .unwrap();
    assert!(repo.delete("codex", "hermes").await.unwrap());
    assert!(repo.get(&key, "codex", "hermes").await.unwrap().is_none());
    // openclaw's session is untouched.
    assert!(repo.get(&key, "codex", "openclaw").await.unwrap().is_some());
}

#[tokio::test]
async fn list_pending_refresh_returns_label_too() {
    let (_dir, repo, key) = fresh_repo().await;
    let now = unix_now();
    repo.create(&key, "codex", "hermes", "rt", Some("at"), Some(now), "")
        .await
        .unwrap();
    repo.create(&key, "codex", "openclaw", "rt", Some("at"), Some(now), "")
        .await
        .unwrap();
    let pending = repo.list_pending_refresh(now + 60).await.unwrap();
    assert_eq!(pending.len(), 2);
    assert!(
        pending
            .iter()
            .any(|p| p == &("codex".to_string(), "hermes".to_string()))
    );
    assert!(
        pending
            .iter()
            .any(|p| p == &("codex".to_string(), "openclaw".to_string()))
    );
}

#[tokio::test]
async fn list_all_returns_all_label_pairs() {
    let (_dir, repo, key) = fresh_repo().await;
    repo.create(&key, "codex", DEF, "rt", Some("at"), Some(100), "")
        .await
        .unwrap();
    repo.create(&key, "codex", "hermes", "rt", Some("at"), Some(200), "")
        .await
        .unwrap();
    repo.create(&key, "anthropic-oauth", DEF, "rt", None, None, "")
        .await
        .unwrap();
    let rows = repo.list_all().await.unwrap();
    assert_eq!(rows.len(), 3);
}
