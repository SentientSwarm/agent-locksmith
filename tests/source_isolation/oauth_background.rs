use super::*;

async fn start_refresh(
    h: &Harness,
) -> (
    tokio::sync::oneshot::Sender<()>,
    tokio::task::JoinHandle<()>,
) {
    start_refresh_with(h, agent_locksmith::client_pool::unproxied_default().into()).await
}

async fn start_refresh_with(
    h: &Harness,
    clients: agent_locksmith::client_pool::OauthClients,
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
        clients,
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

fn clients(egress_proxy: Option<&str>) -> agent_locksmith::client_pool::OauthClients {
    let line = egress_proxy.map_or(String::new(), |p| format!("egress_proxy: \"{p}\"\n"));
    let cfg = agent_locksmith::config::parse_config_str(&format!(
        "listen:\n  host: 127.0.0.1\n  port: 9200\n{line}"
    ))
    .unwrap();
    agent_locksmith::client_pool::OauthClients::new(&cfg)
}

async fn expired_selected(h: &Harness) {
    select(h, Some("selected"), false).await;
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
}

/// AGENT-269 — the background task refreshes a proxied route through the
/// egress proxy; the provider is never reached directly.
#[tokio::test]
async fn background_refresh_of_a_proxied_route_goes_through_the_proxy() {
    let proxy = MockServer::start().await;
    let h = setup_with(true, Some(&proxy.uri())).await;
    expired_selected(&h).await;
    Mock::given(method("POST"))
        .and(path("/selected-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token":"private-access-X", "expires_in":3600})))
        .expect(1)
        .mount(&proxy)
        .await;
    let (stop, task) = start_refresh_with(&h, clients(Some(&proxy.uri()))).await;
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        loop {
            let s = h
                .sessions
                .get(&h.sealing_key, "codex", "selected")
                .await
                .unwrap()
                .unwrap();
            if s.access_token.unwrap().expose_secret() == "private-access-X" {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    stop.send(()).unwrap();
    task.await.unwrap();
    assert!(h.mock.received_requests().await.unwrap().is_empty());
}

/// AGENT-269 — with no egress configured, the background task skips a
/// proxied route's session: no direct call, and no degradation.
#[tokio::test]
async fn background_refresh_without_egress_skips_the_session() {
    let h = setup_with(true, None).await;
    expired_selected(&h).await;
    let (stop, task) = start_refresh_with(&h, clients(None)).await;
    // The first tick runs at once; give it time to act if it were going to.
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    stop.send(()).unwrap();
    task.await.unwrap();
    assert!(h.mock.received_requests().await.unwrap().is_empty());
    let s = h
        .sessions
        .get(&h.sealing_key, "codex", "selected")
        .await
        .unwrap()
        .unwrap();
    assert!(!s.degraded && !s.refresh_pending);
}
