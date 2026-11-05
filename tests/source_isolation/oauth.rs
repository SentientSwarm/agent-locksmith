use super::*;
use axum::http::StatusCode;

async fn select(h: &Harness, label: Option<&str>, pkce: bool) {
    let auth = if pkce {
        AuthSpec::OauthPkce {
            client_id: "selected-client".into(),
            redirect_uri: "http://127.0.0.1/cb".into(),
            scopes: vec![],
            auth_url: format!("{}/auth", h.mock.uri()),
            token_url: format!("{}/selected-token", h.mock.uri()),
            session_label: label.map(str::to_string),
        }
    } else {
        AuthSpec::OauthDeviceCode {
            client_id: "selected-client".into(),
            scopes: vec![],
            device_url: format!("{}/device", h.mock.uri()),
            token_url: format!("{}/selected-token", h.mock.uri()),
            session_label: label.map(str::to_string),
        }
    };
    let id: i64 = sqlx::query_scalar("SELECT id FROM agents WHERE name = 'oauth-test'")
        .fetch_one(&h.pool)
        .await
        .unwrap();
    h.bindings.set(id, "codex", &auth).await.unwrap();
}

async fn call(h: &Harness) -> axum_test::TestResponse {
    h.server
        .get("/api/codex/v1/whatever")
        .add_header("authorization", &h.bearer_header)
        .add_header("x-api-key", "caller-private-sentinel")
        .await
}

#[tokio::test]
async fn selected_oauth_requires_explicit_nonempty_label() {
    for label in [None, Some(""), Some(" ")] {
        let h = setup().await;
        seed_session(
            &h,
            "private-default-refresh",
            Some("private-default-access"),
            Some(unix_now() + 3600),
        )
        .await;
        select(&h, label, false).await;
        call(&h)
            .await
            .assert_status(StatusCode::SERVICE_UNAVAILABLE);
        assert!(h.mock.received_requests().await.unwrap().is_empty());
    }
}

#[tokio::test]
async fn selected_oauth_cross_kind_uses_selected_session() {
    for pkce in [false, true] {
        let h = setup().await;
        select(&h, Some("selected"), pkce).await;
        h.sessions
            .create(
                &h.sealing_key,
                "codex",
                "selected",
                "private-refresh-X",
                Some("private-access-X"),
                Some(unix_now() + 3600),
                "",
            )
            .await
            .unwrap();
        let mut row = h.registrations.get("codex").await.unwrap().unwrap();
        row.auth = AuthSpec::Bearer {
            env_var: "UNSELECTED_TEMPLATE".into(),
        };
        h.registrations.upsert(&row).await.unwrap();
        h.catalog.store(Arc::new(
            Catalog::from_repo(&h.registrations).await.unwrap(),
        ));
        Mock::given(method("GET"))
            .and(header("authorization", "Bearer private-access-X"))
            .respond_with(ResponseTemplate::new(200).set_body_string("X"))
            .mount(&h.mock)
            .await;
        let response = call(&h).await;
        response.assert_status_ok();
        assert_eq!(response.text(), "X");
        let requests = h.mock.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1);
        let headers = format!("{:?}", requests[0].headers);
        assert!(!headers.contains("caller-private-sentinel"));
        assert!(!headers.contains(&h.bearer_header));
        let rows = h
            .audit
            .query(&AuditFilter::default(), AuditPage::default())
            .await
            .unwrap();
        let details = rows.last().unwrap().details.as_ref().unwrap();
        assert_eq!(details["oauth_session_label"], "selected");
        assert_eq!(
            details["auth_mode"],
            if pkce {
                "oauth_pkce"
            } else {
                "oauth_device_code"
            }
        );
        assert!(!format!("{rows:?}").contains("private-"));
    }
}

#[tokio::test]
async fn selected_empty_oauth_access_token_never_dispatches() {
    let h = setup().await;
    seed_session(&h, "private-refresh", Some(""), Some(unix_now() + 3600)).await;
    call(&h)
        .await
        .assert_status(StatusCode::SERVICE_UNAVAILABLE);
    assert!(h.mock.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn selected_oauth_unseal_failure_is_unavailable() {
    let h = setup().await;
    seed_session(
        &h,
        "private-refresh",
        Some("private-access"),
        Some(unix_now() + 3600),
    )
    .await;
    sqlx::query("UPDATE oauth_sessions SET access_token_ciphertext = X'001122'")
        .execute(&h.pool)
        .await
        .unwrap();
    call(&h)
        .await
        .assert_status(StatusCode::SERVICE_UNAVAILABLE);
    assert!(h.mock.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn selected_oauth_missing_degraded_and_revoked_never_use_default() {
    for pkce in [false, true] {
        let h = setup().await;
        select(&h, Some("selected"), pkce).await;
        seed_session(
            &h,
            "private-default-refresh",
            Some("private-default"),
            Some(unix_now() + 3600),
        )
        .await;
        call(&h)
            .await
            .assert_status(StatusCode::SERVICE_UNAVAILABLE);
        h.sessions
            .create(
                &h.sealing_key,
                "codex",
                "selected",
                "private-refresh-X",
                Some("private-access-X"),
                Some(unix_now() + 3600),
                "",
            )
            .await
            .unwrap();
        h.sessions
            .mark_degraded(
                &h.sessions
                    .get(&h.sealing_key, "codex", "selected")
                    .await
                    .unwrap()
                    .unwrap(),
            )
            .await
            .unwrap();
        call(&h)
            .await
            .assert_status(StatusCode::SERVICE_UNAVAILABLE);
        h.sessions.delete("codex", "selected").await.unwrap();
        call(&h)
            .await
            .assert_status(StatusCode::SERVICE_UNAVAILABLE);
        assert!(h.mock.received_requests().await.unwrap().is_empty());
    }
}

#[path = "oauth_refresh.rs"]
mod refresh;

#[path = "oauth_background.rs"]
mod background;

#[path = "oauth_consistency.rs"]
mod consistency;
