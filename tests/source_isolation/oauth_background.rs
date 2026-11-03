use super::*;

async fn start_refresh(
    h: &Harness,
) -> (
    tokio::sync::oneshot::Sender<()>,
    tokio::task::JoinHandle<()>,
) {
    let (tx, rx) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(agent_locksmith::oauth::refresh::run(
        h.sessions.clone(),
        h.catalog.clone(),
        h.bindings.clone(),
        h.sealing_key.clone(),
        RefreshLockMap::new(),
        None,
        async {
            let _ = rx.await;
        },
    ));
    (tx, task)
}

#[tokio::test]
async fn background_refresh_uses_selected_metadata_after_template_edit() {
    let h = setup().await;
    select(&h, Some("selected"), true).await;
    h.sessions
        .create(
            &h.sealing_key,
            "codex",
            "selected",
            "private-refresh-X",
            Some("expired-X"),
            Some(unix_now() - 60),
            "",
        )
        .await
        .unwrap();
    Mock::given(method("POST"))
        .and(path("/selected-token"))
        .and(wiremock::matchers::body_string_contains(
            "refresh_token=private-refresh-X",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token":"private-access-X", "expires_in":3600})))
        .expect(1)
        .mount(&h.mock)
        .await;
    let (stop, task) = start_refresh(&h).await;
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        loop {
            let session = h
                .sessions
                .get(&h.sealing_key, "codex", "selected")
                .await
                .unwrap()
                .unwrap();
            if session.access_token.unwrap().expose_secret() == "private-access-X" {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    stop.send(()).unwrap();
    task.await.unwrap();
    let requests = h.mock.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].url.path(), "/selected-token");
}
