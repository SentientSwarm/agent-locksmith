//! Real encrypted session repository, label selection and refresh locking.
use super::fixture::Fixture;
use super::{denied, forwarded, record};
use agent_locksmith::app::OauthRuntime;
use agent_locksmith::oauth::refresh::RefreshLockMap;
use agent_locksmith::oauth::{OauthSessionRepository, SealingKey};
use agent_locksmith::registrations::AuthSpec;
use serde_json::{Value, json};
use std::time::{SystemTime, UNIX_EPOCH};
use wiremock::matchers::{method, path};
use wiremock::{Mock, ResponseTemplate};

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn spec(uri: &str, label: Option<&str>) -> AuthSpec {
    AuthSpec::OauthDeviceCode {
        client_id: "local-proof".into(),
        scopes: vec![],
        device_url: format!("{uri}/device"),
        token_url: format!("{uri}/token"),
        session_label: label.map(str::to_string),
    }
}

async fn setup() -> (Fixture, OauthRuntime) {
    let mut h = Fixture::new(false, false).await;
    let runtime = OauthRuntime {
        sessions: OauthSessionRepository::new(h.store.pool.clone()),
        sealing_key: SealingKey::generate().unwrap(),
        locks: RefreshLockMap::new(),
        refresh_client: reqwest::Client::new(),
    };
    let mut row = h.store.registrations.get("proof").await.unwrap().unwrap();
    row.auth = spec(&h.mock.uri(), None);
    h.store.registrations.upsert(&row).await.unwrap();
    h.store
        .overrides
        .set(h.agent_id, "proof", &spec(&h.mock.uri(), Some("selected")))
        .await
        .unwrap();
    h.refresh_catalog().await;
    h.activate_oauth(runtime.clone());
    (h, runtime)
}

async fn seed(runtime: &OauthRuntime, label: &str, value: &str, expires: i64) {
    runtime
        .sessions
        .create(
            &runtime.sealing_key,
            "proof",
            label,
            "synthetic-refresh",
            Some(value),
            Some(expires),
            "",
        )
        .await
        .unwrap();
}

async fn reject_refresh(h: &Fixture) {
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(401).set_body_string("invalid_grant"))
        .expect(1)
        .mount(&h.mock)
        .await;
}

async fn label_failure(rows: &mut Vec<Value>) {
    let (h, runtime) = setup().await;
    seed(&runtime, "default", "proof-default", now() + 3600).await;
    seed(&runtime, "selected", "proof-selected", now() + 3600).await;
    record(
        rows,
        "OAuth selected label",
        h.request("proof").await,
        forwarded("selected"),
    );
    runtime.sessions.delete("proof", "selected").await.unwrap();
    record(
        rows,
        "OAuth missing selected label does not use default",
        h.request("proof").await,
        denied(503),
    );
    seed(&runtime, "selected", "expired-selected", now() - 60).await;
    reject_refresh(&h).await;
    record(
        rows,
        "OAuth selected refresh failure does not use default",
        h.request("proof").await,
        denied(503),
    );
    check_degraded_labels(rows, &runtime).await;
}

async fn check_degraded_labels(rows: &mut Vec<Value>, runtime: &OauthRuntime) {
    let default = runtime
        .sessions
        .get(&runtime.sealing_key, "proof", "default")
        .await
        .unwrap()
        .unwrap();
    let selected = runtime
        .sessions
        .get(&runtime.sealing_key, "proof", "selected")
        .await
        .unwrap()
        .unwrap();
    record(
        rows,
        "OAuth failed refresh degrades only selected label",
        json!({"selected": selected.degraded, "default": default.degraded}),
        json!({"selected": true, "default": false}),
    );
}

async fn refresh_concurrency(rows: &mut Vec<Value>) {
    let (h, runtime) = setup().await;
    seed(&runtime, "selected", "expired-selected", now() - 60).await;
    Mock::given(method("POST")).and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_delay(std::time::Duration::from_millis(50))
            .set_body_json(json!({"access_token": "proof-selected", "token_type": "Bearer", "expires_in": 3600})))
        .mount(&h.mock).await;
    let replies = futures_util::future::join_all((0..6).map(|_| h.request("proof"))).await;
    let requests = h.mock.received_requests().await.unwrap();
    let token_calls = requests
        .iter()
        .filter(|r| r.method == "POST" && r.url.path() == "/token")
        .count();
    let upstream_calls = requests.iter().filter(|r| r.method == "GET").count();
    let correct_replies = replies
        .iter()
        .filter(|r| r["status"] == 200 && r["account"] == "selected")
        .count();
    record(
        rows,
        "OAuth concurrent expired-session calls share one refresh",
        json!({"refreshes": token_calls, "upstream_calls": upstream_calls, "correct_replies": correct_replies}),
        json!({"refreshes": 1, "upstream_calls": 6, "correct_replies": 6}),
    );
}

pub async fn run(rows: &mut Vec<Value>) {
    label_failure(rows).await;
    refresh_concurrency(rows).await;
}
