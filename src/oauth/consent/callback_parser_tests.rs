use super::*;

#[tokio::test]
async fn callback_issuer_controlled_state_and_path_are_checked_before_claim() {
    let f = Fixture::new().await;
    let attempt = f.start("strict").await;
    let url = reqwest::Url::parse(attempt["authorization_url"].as_str().unwrap()).unwrap();
    let state = url
        .query_pairs()
        .find(|(k, _)| k == "state")
        .unwrap()
        .1
        .into_owned();
    let p = &f.rt.config.profiles[0];
    refuse_claims(&f, &state, &attempt).await;
    f.rt.claim(
        &state,
        Some(&p.issuer),
        "127.0.0.1:19294",
        "/oauth/callback",
    )
    .await
    .unwrap();
    f.rt.pool.close().await;
}

#[tokio::test]
async fn callback_issuer_parser_rejects_absolute_and_encoded_paths() {
    let f = Fixture::new().await;
    let query = format!(
        "state={}&iss=https%3A%2F%2F127.0.0.1%3A19293&code=code",
        "s".repeat(43)
    );
    for path in [
        "https://127.0.0.1:19294/oauth/callback",
        "/oauth/%63allback",
        "/oauth/callback/slack/",
        "/oauth/callback/%73lack",
    ] {
        let req = axum::http::Request::builder()
            .uri(format!("{path}?{query}"))
            .header("host", "127.0.0.1:19294")
            .body(axum::body::Body::empty())
            .unwrap();
        assert!(server::parameters(&f.rt, &req).is_err(), "{path}");
    }
    f.rt.pool.close().await;
}

async fn refuse_claims(f: &Fixture, state: &str, attempt: &Value) {
    let p = &f.rt.config.profiles[0];
    for (issuer, path) in [
        (None, "/oauth/callback"),
        (None, "/oauth/callback/slack"),
        (Some(p.issuer.as_str()), "/oauth/callback/slack"),
    ] {
        assert!(
            f.rt.claim(state, issuer, "127.0.0.1:19294", path)
                .await
                .is_err()
        );
        assert_eq!(
            f.rt.poll("owner", "fixture", attempt["attempt_id"].as_str().unwrap())
                .await
                .unwrap()["state"],
            "pending"
        );
    }
}

#[tokio::test]
async fn callback_issuer_parser_rejects_duplicate_host() {
    let f = Fixture::new().await;
    let mut req = axum::http::Request::builder()
        .uri(format!(
            "/oauth/callback/slack?state={}&code=code",
            "s".repeat(43)
        ))
        .header("host", "127.0.0.1:19294")
        .body(axum::body::Body::empty())
        .unwrap();
    req.headers_mut()
        .append("host", "127.0.0.1:19294".parse().unwrap());
    assert!(server::parameters(&f.rt, &req).is_err());
    f.rt.pool.close().await;
}
