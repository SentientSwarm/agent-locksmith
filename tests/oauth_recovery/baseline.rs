use super::support::*;

#[tokio::test]
async fn interrupted_exchange_is_not_replayed_after_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.db");
    let pool = migrations::open_and_migrate(&path).await.unwrap();
    let repo = OauthSessionRepository::new(pool.clone());
    let key = SealingKey::generate().unwrap();
    let session = seed(&repo, &key).await;
    let server = held_provider().await;
    let selection = selection(&server);
    let client = reqwest::Client::new();
    let pending = start(
        repo,
        key.clone(),
        selection.clone(),
        client.clone(),
        session,
    );
    wait_arrival(&server).await;
    pending.abort();
    assert!(pending.await.unwrap_err().is_cancelled());
    pool.close().await;
    assert_no_replay(&path, &key, &selection, &client, &server).await;
}

fn start(
    repo: OauthSessionRepository,
    key: SealingKey,
    selection: AuthSpec,
    client: reqwest::Client,
    session: agent_locksmith::oauth::OauthSession,
) -> tokio::task::JoinHandle<
    Result<agent_locksmith::oauth::OauthSession, agent_locksmith::oauth::refresh::RefreshError>,
> {
    tokio::spawn(async move {
        refresh_selected_session(&repo, &selection, &key, &client, &session).await
    })
}

async fn assert_no_replay(
    path: &std::path::Path,
    key: &SealingKey,
    selection: &AuthSpec,
    client: &reqwest::Client,
    server: &MockServer,
) {
    let repo = OauthSessionRepository::new(migrations::open_and_migrate(path).await.unwrap());
    let current = repo.get(key, "fixture", "reader").await.unwrap().unwrap();
    let result = tokio::time::timeout(
        Duration::from_millis(250),
        refresh_selected_session(&repo, selection, key, client, &current),
    )
    .await;
    let arrivals = server.received_requests().await.unwrap().len();
    println!("token arrivals after interrupted exchange and reopen: {arrivals}");
    assert_eq!(arrivals, 1, "uncertain refresh token was sent again");
    assert!(
        result.is_ok_and(|r| r.is_err()),
        "uncertain refresh must refuse"
    );
    assert!(
        repo.list_pending_refresh(i64::MAX)
            .await
            .unwrap()
            .is_empty()
    );
}
