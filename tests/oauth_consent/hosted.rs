//! Actual hosted-fixture profile, public callback authority over an explicit local TLS route.
use super::*;

pub async fn public_callback() {
    let mut f = Fixture::new();
    let t = Twin::start(&f);
    let port = configure(&f, &t);
    let public = format!("https://callback.example.test:{port}/oauth/callback");
    let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
    let ca_key = rcgen::KeyPair::generate().unwrap();
    let ca = ca_params.self_signed(&ca_key).unwrap();
    let leaf_key = rcgen::KeyPair::generate().unwrap();
    let leaf = rcgen::CertificateParams::new(vec!["callback.example.test".into()])
        .unwrap()
        .signed_by(&leaf_key, &ca, &ca_key)
        .unwrap();
    std::fs::write(f.path().join("callback.pem"), leaf.pem()).unwrap();
    std::fs::write(f.path().join("callback.key"), leaf_key.serialize_pem()).unwrap();
    let path = f.path().join("config.yaml");
    let mut config: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    config["oauth_consent"]["callback"]["cert_path"] = json!(f.path().join("callback.pem"));
    config["oauth_consent"]["callback"]["key_path"] = json!(f.path().join("callback.key"));
    let p = &mut config["oauth_consent"]["profiles"][0];
    p["kind"] = json!("linear-hosted-fixture-v1");
    p["selected_tools"] = json!(["get_workspace"]);
    p["redirect_uri"] = json!(public);
    let mut other = p.clone();
    other["id"] = json!("other");
    other["redirect_uri"] = json!(format!("https://other.example.test:{port}/oauth/callback"));
    config["oauth_consent"]["profiles"]
        .as_array_mut()
        .unwrap()
        .push(other);
    std::fs::write(&path, config.to_string()).unwrap();
    start(&mut f).await;
    let auth = json!({"kind":"oauth_pkce","client_id":"fixture-client","redirect_uri":public,"scopes":["read"],"auth_url":t.url("/authorize"),"token_url":t.url("/token")});
    assert_eq!(request(&f,"PUT","/admin/operator/tools/fixture",Some(json!({"upstream":t.url("/mcp/readonly"),"auth":auth,"egress":"direct","protocol":"mcp_streamable_http","mcp":{"protocol_version":"2025-11-25","allow_private_destination":true,"compact":true}}))).await.0,200);
    let created = connect(&f, "public");
    let started = reqwest::Url::parse(created["authorization_url"].as_str().unwrap()).unwrap();
    assert_eq!(
        started
            .query_pairs()
            .find(|(k, _)| k == "redirect_uri")
            .unwrap()
            .1,
        public
    );
    let mut callback = reqwest::Url::parse(&callback(&t, port, &created)).unwrap();
    callback.set_host(Some("callback.example.test")).unwrap();
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .add_root_certificate(reqwest::Certificate::from_pem(ca.pem().as_bytes()).unwrap())
        .resolve(
            "callback.example.test",
            format!("127.0.0.1:{port}").parse().unwrap(),
        )
        .build()
        .unwrap();
    for header in ["wrong-authority", "forwarded"] {
        let r = client.get(callback.clone());
        let r = if header == "wrong-authority" {
            r.header("host", format!("other.example.test:{port}"))
        } else {
            r.header("x-forwarded-host", format!("callback.example.test:{port}"))
        };
        assert_eq!(r.send().await.unwrap().status(), 400);
        assert!(
            !f.path().join("counts.json").exists(),
            "receiver writes first count on first arrival; callback refusals have none"
        );
    }
    assert_eq!(
        client.get(callback.clone()).send().await.unwrap().status(),
        200
    );
    assert_eq!(
        client.get(callback).send().await.unwrap().status(),
        400,
        "single-use callback"
    );
    let account = f.op(&["oauth", "account-status", "fixture", "--label", "public"]);
    assert_eq!(account["kind"], "linear_hosted_fixture_v1");
    assert_eq!(account["state"], "connected_unbound");
    assert_eq!(counts(&f)["token"], 1);
    assert_eq!(counts(&f)["workspace"], 1);
    assert_eq!(counts(&f)["user"], 1);
    assert_eq!(counts(&f).get("tool"), None);
    f.stop();
    t.stop();
    println!(
        "hosted public callback/local TLS bind: wrong selected authority/forwarded/replay refused; one token and both identities; no TOOL; joined"
    );
}

pub async fn prior_upgrade() {
    let old =
        std::env::var("LOCKSMITH_HOSTED_PRIOR_DAEMON").expect("explicit retained schema-18 daemon");
    let mut f = Fixture::new();
    f.start(&old).await;
    f.stop();
    let pool =
        sqlx::SqlitePool::connect(&format!("sqlite://{}", f.path().join("state.db").display()))
            .await
            .unwrap();
    let version: i64 = sqlx::query_scalar("SELECT max(version) FROM _sqlx_migrations")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(version, 18, "actual prior binary positive control");
    pool.close().await;
    f.start(process::DAEMON).await;
    f.stop();
    let mut command = process::command(&old);
    command.arg("--config").arg(f.path().join("config.yaml"));
    let result = process::run(command);
    assert!(!result.status.success());
    let logs = format!(
        "{}{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(
        logs.contains("19") && logs.contains("migration"),
        "old schema refusal, not fixture setup"
    );
    assert!(
        f.http.get(f.url("/livez")).send().await.is_err(),
        "no old listener"
    );
    f.start(process::DAEMON).await;
    let pool =
        sqlx::SqlitePool::connect(&format!("sqlite://{}", f.path().join("state.db").display()))
            .await
            .unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT max(version) FROM _sqlx_migrations")
            .fetch_one(&pool)
            .await
            .unwrap(),
        23
    );
    pool.close().await;
    f.stop();
    println!(
        "actual prior schema-18 positive -> current schema 23 -> prior refusal/no listener -> current reopen; all joined"
    );
}
