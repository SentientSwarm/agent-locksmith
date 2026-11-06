use super::*;

#[tokio::test]
async fn callback_issuer_canonical_collision_and_separation() {
    let f = fixture().await;
    let mut c = f.rt.config.clone();
    c.profiles[0].redirect_uri = "https://callback.example.test/oauth/callback/slack".into();
    let second = second_issuer(&c.profiles[0]);
    c.profiles.push(second);
    assert!(
        c.validate().is_err(),
        "same received URI cannot identify two issuers"
    );
    c.profiles[1].redirect_uri = "https://second.example.test/oauth/callback/slack".into();
    assert!(
        c.validate().is_ok(),
        "separate issuer redirects remain supported"
    );
    c.profiles[1].redirect_uri = "https://callback.example.test/oauth/callback".into();
    assert!(
        c.validate().is_ok(),
        "mandatory-issuer generic route is distinct"
    );
    f.rt.pool.close().await;
}

#[tokio::test]
async fn callback_issuer_redirect_change_requires_new_client_generation() {
    let mut f = fixture().await;
    f.rt.set_client("owner", "fixture", "fixture", 1, "invented-first")
        .await
        .unwrap();
    let old = change_redirect(&mut f).await;
    old_only(&f, &old).await;
    assert!(
        f.rt.set_client("owner", "fixture", "fixture", 1, "invented-new")
            .await
            .is_err()
    );
    advance(&mut f, 2).await;
    f.rt.set_client("owner", "fixture", "fixture", 2, "invented-new")
        .await
        .unwrap();
    let mut c = f.rt.pool.acquire().await.unwrap();
    clients::current(&mut c, "owner", &f.rt.config.profiles[0])
        .await
        .unwrap();
    assert!(clients::current(&mut c, "owner", &old).await.is_err());
    drop(c);
    f.rt.pool.close().await;
}

fn second_issuer(first: &config::Profile) -> config::Profile {
    let mut second = first.clone();
    second.id = "second".into();
    second.issuer = "https://127.0.0.1:19295".into();
    second.authorization_endpoint = format!("{}/oauth/v2_user/authorize", second.issuer);
    second.token_endpoint = format!("{}/api/oauth.v2.user.access", second.issuer);
    second.resource = second.issuer.clone();
    second.redirect_uri = "https://CALLBACK.example.test:443/oauth/callback/slack".into();
    second
}

async fn old_only(f: &Fixture, old: &config::Profile) {
    let mut c = f.rt.pool.acquire().await.unwrap();
    assert!(
        clients::current(&mut c, "owner", &f.rt.config.profiles[0])
            .await
            .is_err()
    );
    clients::current(&mut c, "owner", old).await.unwrap();
    drop(c);
}

async fn change_redirect(f: &mut Fixture) -> config::Profile {
    let old = f.rt.config.profiles[0].clone();
    Arc::get_mut(&mut f.rt).unwrap().config.profiles[0]
        .redirect_uri
        .push_str("/slack");
    f.rt.config.validate().unwrap();
    let mut r = f.repo.get("fixture").await.unwrap().unwrap();
    r.auth = f.rt.config.profiles[0].auth_spec();
    f.repo.upsert(&r).await.unwrap();
    old
}
