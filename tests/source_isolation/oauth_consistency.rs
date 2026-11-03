//! Shared-session metadata must agree before any cached-token use or refresh.
use super::*;

fn spec(uri: &str, pkce: bool, client: &str, token_path: &str) -> AuthSpec {
    if pkce {
        AuthSpec::OauthPkce {
            client_id: client.into(),
            scopes: vec![],
            redirect_uri: format!("{uri}/cb"),
            auth_url: format!("{uri}/auth"),
            token_url: format!("{uri}{token_path}"),
            session_label: Some("shared".into()),
        }
    } else {
        AuthSpec::OauthDeviceCode {
            client_id: client.into(),
            scopes: vec![],
            device_url: format!("{uri}/device"),
            token_url: format!("{uri}{token_path}"),
            session_label: Some("shared".into()),
        }
    }
}

async fn fixture(pkce: bool, conflicting: bool, expired: bool) -> Harness {
    let mut h = setup().await;
    let agents = AgentRepository::new(h.pool.clone());
    let first = agents.get_by_name("oauth-test").await.unwrap().unwrap();
    let (pid, token) = agents
        .create("qa-second", None, Some(&["codex".into()]), None, None, None)
        .await
        .unwrap();
    h.bearer_header = format!("Bearer lk_{pid}.{}", token.expose_secret());
    let second = agents.get_by_name("qa-second").await.unwrap().unwrap();
    let chosen = spec(&h.mock.uri(), pkce, "qa-client-X", "/qa-token-X");
    h.bindings.set(first.id, "codex", &chosen).await.unwrap();
    let other = if conflicting {
        spec(&h.mock.uri(), pkce, "qa-client-Y", "/qa-token-Y")
    } else {
        chosen
    };
    h.bindings.set(second.id, "codex", &other).await.unwrap();
    h.sessions
        .create(
            &h.sealing_key,
            "codex",
            "shared",
            "qa-private-refresh-X",
            Some(if expired {
                "qa-expired-X"
            } else {
                "qa-private-access-X"
            }),
            Some(if expired {
                unix_now() - 60
            } else {
                unix_now() + 3600
            }),
            "",
        )
        .await
        .unwrap();
    for (endpoint, access) in [
        ("/qa-token-X", "qa-private-access-X"),
        ("/qa-token-Y", "qa-private-access-Y"),
    ] {
        Mock::given(method("POST"))
            .and(path(endpoint))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"access_token":access,"expires_in":3600})),
            )
            .mount(&h.mock)
            .await;
    }
    for (value, account) in [
        ("Bearer qa-private-access-X", "account-X"),
        ("Bearer qa-private-access-Y", "account-Y"),
    ] {
        Mock::given(method("GET"))
            .and(header("authorization", value))
            .respond_with(ResponseTemplate::new(200).set_body_string(account))
            .mount(&h.mock)
            .await;
    }
    h
}

async fn probe(pkce: bool, conflicting: bool, expired: bool) {
    let h = fixture(pkce, conflicting, expired).await;
    let capture = logs::Capture::default();
    let _guard = capture.start();
    let response = h
        .server
        .get("/api/codex/v1/whatever")
        .add_header("authorization", &h.bearer_header)
        .await;
    let requests = h.mock.received_requests().await.unwrap();
    let selected = requests
        .iter()
        .filter(|r| r.method == "POST" && r.url.path() == "/qa-token-X")
        .count();
    let alternate = requests
        .iter()
        .filter(|r| r.method == "POST" && r.url.path() == "/qa-token-Y")
        .count();
    let operations = requests.iter().filter(|r| r.method == "GET").count();
    println!(
        "QA_OBSERVATION {}",
        json!({"pkce":pkce,"conflicting":conflicting,
        "status":response.status_code().as_u16(),"endpoint_X_exchanges":selected,
        "endpoint_Y_exchanges":alternate,"upstream_operations":operations,"body":response.text(),
        "refresh_X_sent_to_Y":requests.iter().any(|r| r.url.path() == "/qa-token-Y" && String::from_utf8_lossy(&r.body).contains("refresh_token=qa-private-refresh-X"))})
    );
    let audit = h
        .audit
        .query(&AuditFilter::default(), AuditPage::default())
        .await
        .unwrap();
    let surfaces = format!("{}{}{audit:?}", response.text(), capture.text());
    for value in [
        "qa-private-refresh-X",
        "qa-private-access-X",
        "qa-private-access-Y",
    ] {
        assert!(!surfaces.contains(value), "credential sentinel disclosed");
    }
    check(
        response,
        conflicting,
        expired,
        (selected, alternate, operations),
    );
}

fn check(
    response: axum_test::TestResponse,
    conflicting: bool,
    expired: bool,
    counts: (usize, usize, usize),
) {
    if conflicting {
        assert_eq!(
            counts,
            (0, 0, 0),
            "conflicting shared-session metadata must fail before any exchange/operation"
        );
        response.assert_status(axum::http::StatusCode::SERVICE_UNAVAILABLE);
        assert!(response.json::<serde_json::Value>()["error"]["code"].is_string());
    } else {
        response.assert_status_ok();
        assert_eq!(response.text(), "account-X");
        assert_eq!(counts, (usize::from(expired), 0, 1));
    }
}

#[tokio::test]
async fn conflicting_pkce_refresh_must_not_exchange() {
    probe(true, true, true).await;
}
#[tokio::test]
async fn conflicting_device_refresh_must_not_exchange() {
    probe(false, true, true).await;
}
#[tokio::test]
async fn consistent_shared_refresh_remains_allowed() {
    probe(false, false, true).await;
    probe(true, false, true).await;
}

#[tokio::test]
async fn conflicting_cached_shared_sessions_are_denied() {
    probe(false, true, false).await;
    probe(true, true, false).await;
}

#[tokio::test]
async fn consistent_cached_shared_sessions_remain_allowed() {
    probe(false, false, false).await;
    probe(true, false, false).await;
}
