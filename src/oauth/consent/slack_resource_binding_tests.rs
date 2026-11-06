use super::*;

async fn published(f: &Fixture) -> (Value, AuthSpec) {
    let started =
        f.rt.start("owner", "fixture", &start_request(f).await)
            .await
            .unwrap();
    let url = reqwest::Url::parse(started["authorization_url"].as_str().unwrap()).unwrap();
    let state = url
        .query_pairs()
        .find(|(k, _)| k == "state")
        .unwrap()
        .1
        .into_owned();
    let p = &f.rt.config.profiles[0];
    let claim =
        f.rt.claim(
            &state,
            Some(&p.issuer),
            "127.0.0.1:19294",
            "/oauth/callback",
        )
        .await
        .unwrap();
    let token = slack_token::decode(p, &json!({"ok":true,"access_token":"invented-access","refresh_token":"invented-refresh","token_type":"user","authed_user":{"id":"UTEST001","scope":"channels:history,search:read.public"},"team":{"id":"TTEST001"}})).unwrap();
    f.rt.quarantine(&claim, &token).await.unwrap();
    f.rt.publish(&claim, &token).await.unwrap();
    selection(f).await
}

async fn selection(f: &Fixture) -> (Value, AuthSpec) {
    let view = f.rt.account("owner", "fixture", "reader").await.unwrap();
    let mut c = f.rt.pool.acquire().await.unwrap();
    let selection =
        f.rt.native_selection(
            &mut c,
            "owner",
            "fixture",
            "reader",
            view["revision"].as_str().unwrap(),
        )
        .await
        .unwrap();
    f.rt.native_account(&mut c, "fixture", &selection)
        .await
        .unwrap();
    (view, selection)
}

#[tokio::test]
async fn slack_resource_change_invalidates_client_account_and_native_binding() {
    let mut f = fixture().await;
    f.rt.set_client("owner", "fixture", "fixture", 1, "invented-client-secret")
        .await
        .unwrap();
    let (before, selection) = published(&f).await;
    let sealed = custody(&f).await;
    let old = f.rt.config.profiles[0].clone();
    Arc::get_mut(&mut f.rt).unwrap().config.profiles[0].resource = old.issuer.clone();
    f.rt.config.validate().unwrap();
    let p = &f.rt.config.profiles[0];
    assert_eq!(p.mcp_endpoint(), old.resource);
    let view = f.rt.account("owner", "fixture", "reader").await.unwrap();
    assert_eq!(view["state"], "reconnect_required");
    assert_eq!(view["token_version"], before["token_version"]);
    assert_eq!(view["refresh_pending"], false);
    stale_refuses(&f, &selection, &view).await;
    refresh_refuses(&f, &view, &sealed).await;
}

#[tokio::test]
async fn slack_resource_canonical_registration_and_owner_binding() {
    let mut f = fixture().await;
    let p = &mut Arc::get_mut(&mut f.rt).unwrap().config.profiles[0];
    p.resource = p.issuer.clone();
    f.rt.config.validate().unwrap();
    f.rt.set_client("owner", "fixture", "fixture", 1, "invented-client-secret")
        .await
        .unwrap();
    check_binding(&f).await;
    published(&f).await;
    let mut r = f.repo.get("fixture").await.unwrap().unwrap();
    let p = &f.rt.config.profiles[0];
    for wrong in [&p.resource, "https://foreign.example.test/mcp"] {
        r.upstream = wrong.into();
        f.repo.upsert(&r).await.unwrap();
        let mut c = f.rt.pool.acquire().await.unwrap();
        assert!(
            store::registration(&mut c, "fixture", Some(p))
                .await
                .is_err()
        );
    }
    let view = f.rt.account("owner", "fixture", "reader").await.unwrap();
    assert_eq!(view["state"], "reconnect_required");
    assert!(f.rt.account("foreign", "fixture", "reader").await.is_err());
}

async fn stale_refuses(f: &Fixture, selection: &AuthSpec, view: &Value) {
    let p = &f.rt.config.profiles[0];
    let mut c = f.rt.pool.acquire().await.unwrap();
    assert!(clients::current(&mut c, "owner", p).await.is_err());
    assert!(
        f.rt.native_account(&mut c, "fixture", selection)
            .await
            .is_err()
    );
    drop(c);
    assert!(
        f.rt.set_client("owner", "fixture", "fixture", 1, "invented-replacement")
            .await
            .is_err()
    );
    assert_eq!(
        f.rt.account("owner", "fixture", "reader").await.unwrap(),
        *view
    );
}

async fn custody(f: &Fixture) -> String {
    sqlx::query_scalar("SELECT hex(access_token_ciphertext)||hex(access_token_nonce)||hex(refresh_token_ciphertext)||hex(refresh_token_nonce)||token_version||refresh_pending FROM oauth_sessions WHERE name='fixture' AND session_label='reader'")
        .fetch_one(&f.rt.pool).await.unwrap()
}

async fn refresh_refuses(f: &Fixture, view: &Value, sealed: &str) {
    let (result, trace) =
        f.rt.refresh(
            "owner",
            "fixture",
            "reader",
            view["revision"].as_str().unwrap(),
        )
        .await;
    assert!(result.is_err());
    assert_eq!(trace["finalization"], "not_started");
    assert_eq!(custody(f).await, sealed);
}
