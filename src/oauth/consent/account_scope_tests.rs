use super::*;
// Reviewer-authored source-only oracle; include within consent::tests.
async fn reviewer_scoped_account(echoed: bool) -> Fixture {
    let f = Fixture::new().await;
    let (_, a) = f.claimed("scope-custody").await;
    let token = if echoed {
        token::decode(
            &f.rt.config.profiles[0],
            br#"{"access_token":"fixture-access","token_type":"Bearer","scope":"read"}"#,
        )
        .unwrap()
    } else {
        f.token()
    };
    f.rt.quarantine(&a, &token).await.unwrap();
    f.rt.publish(&a, &token, None).await.unwrap();
    f
}

#[tokio::test]
async fn reviewer_scope_status_survives_replaced_profile() {
    let mut f = reviewer_scoped_account(true).await;
    let before =
        f.rt.account("owner", "fixture", "scope-custody")
            .await
            .unwrap();
    assert_eq!(before["granted_scope"], json!("read"));
    let p = &mut Arc::get_mut(&mut f.rt).unwrap().config.profiles[0];
    p.kind = "slack-confidential-fixture-v1".into();
    p.expected_workspace = "TTEST001".into();
    p.expected_user = "UTEST001".into();
    p.authorization_endpoint = format!("{}/oauth/v2_user/authorize", p.issuer);
    p.token_endpoint = format!("{}/api/oauth.v2.user.access", p.issuer);
    p.resource = format!("{}/mcp", p.issuer);
    f.rt.config.validate().unwrap();
    let after =
        f.rt.account("owner", "fixture", "scope-custody")
            .await
            .unwrap();
    assert_eq!(after["state"], json!("reconnect_required"));
    assert_eq!(after["requested_scopes"], json!(["read"]));
    assert_eq!(after["granted_scope"], json!("read"));
}

#[tokio::test]
async fn reviewer_scope_status_survives_removed_profile() {
    let mut f = reviewer_scoped_account(true).await;
    Arc::get_mut(&mut f.rt).unwrap().config.profiles[0].id = "different-profile".into();
    f.rt.config.validate().unwrap();
    let after =
        f.rt.account("owner", "fixture", "scope-custody")
            .await
            .unwrap();
    assert_eq!(after["state"], json!("reconnect_required"));
    assert_eq!(after["requested_scopes"], json!(["read"]));
    assert_eq!(after["granted_scope"], json!("read"));
}

#[tokio::test]
async fn reviewer_scope_without_echo_remains_unknown() {
    let f = reviewer_scoped_account(false).await;
    let view =
        f.rt.account("owner", "fixture", "scope-custody")
            .await
            .unwrap();
    assert_eq!(view["requested_scopes"], json!(["read"]));
    assert_eq!(view["granted_scope"], Value::Null);
}
