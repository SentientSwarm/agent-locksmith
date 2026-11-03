use super::fixture::*;
use super::inventory::{add, row};
use agent_locksmith::registrations::AuthSpec;
fn oauth(label: Option<&str>, client: &str, pkce: bool) -> AuthSpec {
    if pkce {
        AuthSpec::OauthPkce {
            client_id: client.into(),
            scopes: vec![],
            redirect_uri: "http://127.0.0.1/callback".into(),
            auth_url: "http://127.0.0.1/authorize".into(),
            token_url: "http://127.0.0.1:1/token".into(),
            session_label: label.map(str::to_string),
        }
    } else {
        AuthSpec::OauthDeviceCode {
            client_id: client.into(),
            scopes: vec![],
            device_url: "http://127.0.0.1/device".into(),
            token_url: "http://127.0.0.1:1/token".into(),
            session_label: label.map(str::to_string),
        }
    }
}
async fn session(f: &Fixture, label: &str) {
    sqlx::query("INSERT INTO oauth_sessions(name,session_label,refresh_token_ciphertext,refresh_token_nonce,access_token_ciphertext,access_token_nonce,created_at,updated_at) VALUES ('oauth', ?, ?, ?, ?, ?,1,1)")
        .bind(label).bind(b"PRIVATE_REFRESH_SENTINEL".as_slice()).bind([0u8;12].as_slice()).bind(b"PRIVATE_ACCESS_SENTINEL".as_slice()).bind([0u8;12].as_slice()).execute(&f.pool).await.unwrap();
}
#[tokio::test]
async fn oauth_known_default_is_explicit_but_conflicts_and_placeholders_require_owner() {
    for pkce in [false, true] {
        let f = fixture(pkce).await;
        let p = f.preview();
        let proposed = row(&p, f.ids[0], "oauth");
        assert_eq!(proposed["action"], "propose");
        assert_eq!(proposed["auth_spec"]["session_label"], "default");
        f.bindings
            .set(
                f.ids[2],
                "oauth",
                &oauth(Some("default"), "other-client", pkce),
            )
            .await
            .unwrap();
        let p = f.preview();
        assert_eq!(
            row(&p, f.ids[0], "oauth")["reason"],
            "conflicting_oauth_session_metadata"
        );
        assert_eq!(row(&p, f.ids[2], "oauth")["action"], "preserve");
        placeholder(&f, pkce).await;
    }
}

async fn fixture(pkce: bool) -> Fixture {
    let f = Fixture::new().await;
    add(&f, "oauth", oauth(None, "client-X", pkce)).await;
    session(&f, "default").await;
    f
}

async fn placeholder(f: &Fixture, pkce: bool) {
    f.bindings
        .set(f.ids[2], "oauth", &oauth(Some("default"), "", pkce))
        .await
        .unwrap();
    let p = f.preview();
    assert_eq!(
        row(&p, f.ids[2], "oauth")["reason"],
        "oauth_owner_reselection_required"
    );
    assert_eq!(row(&p, f.ids[2], "oauth")["auth_spec"]["client_id"], "");
    assert!(!p.to_string().contains("PRIVATE_REFRESH_SENTINEL"));
    assert!(!p.to_string().contains("PRIVATE_ACCESS_SENTINEL"));
}

#[tokio::test]
async fn oauth_reference_apply_never_exchanges_tokens_and_unavailable_sessions_skip() {
    for pkce in [false, true] {
        let (f, tokens) = token_fixture(pkce).await;
        let mut p = f.preview();
        let entry = p["entries"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|e| e["agent_id"] == f.ids[0] && e["registration"] == "oauth")
            .unwrap();
        assert_eq!(entry["action"], "propose");
        entry["selected"] = true.into();
        success(&f.apply(&p));
        success(&f.apply(&p));
        assert!(tokens.received_requests().await.unwrap().is_empty());
        unavailable_sessions(&f, &p).await;
        assert!(tokens.received_requests().await.unwrap().is_empty());
    }
}
async fn token_fixture(pkce: bool) -> (Fixture, wiremock::MockServer) {
    let f = fixture(pkce).await;
    let tokens = wiremock::MockServer::start().await;
    let mut r = f.registrations.get("oauth").await.unwrap().unwrap();
    match &mut r.auth {
        AuthSpec::OauthPkce { token_url, .. } | AuthSpec::OauthDeviceCode { token_url, .. } => {
            *token_url = format!("{}/token", tokens.uri())
        }
        _ => unreachable!(),
    }
    f.registrations.upsert(&r).await.unwrap();
    (f, tokens)
}
async fn unavailable_sessions(f: &Fixture, p: &serde_json::Value) {
    f.exec("UPDATE oauth_sessions SET degraded=1").await;
    conflict(&f.apply(p));
    assert_eq!(
        row(&f.preview(), f.ids[1], "oauth")["reason"],
        "degraded_oauth_session"
    );
    f.exec("DELETE FROM oauth_sessions").await;
    assert_eq!(
        row(&f.preview(), f.ids[1], "oauth")["reason"],
        "missing_oauth_session"
    );
}

#[tokio::test]
async fn corrupt_binding_metadata_blocks_oauth_proposals_without_exporting_input() {
    let f = fixture(false).await;
    assert_eq!(row(&f.preview(), f.ids[0], "oauth")["action"], "propose");
    f.exec("UPDATE agent_credential_overrides SET auth_spec='PRIVATE_INVALID_AUTH_SENTINEL'")
        .await;
    let p = f.preview();
    assert_eq!(row(&p, f.ids[0], "oauth")["action"], "skip");
    assert_eq!(
        row(&p, f.ids[0], "oauth")["reason"],
        "oauth_selection_metadata_unavailable"
    );
    assert_eq!(row(&p, f.ids[2], "api")["action"], "preserve");
    assert!(!p.to_string().contains("PRIVATE_INVALID_AUTH_SENTINEL"));
}
