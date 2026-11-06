use super::*;

async fn set(f: &Fixture, secret: &str, generation: u64) -> (u16, Value) {
    request(
        f,
        "POST",
        "/admin/operator/tools/fixture/oauth/client",
        Some(json!({"profile":"fixture","client_generation":generation,"secret":secret})),
    )
    .await
}
async fn start_refused(f: &Fixture) {
    let view = f.op(&["oauth", "account-status", "fixture", "--label", "reader"]);
    let (status, _) = request(f, "POST", "/admin/operator/tools/fixture/oauth/attempts", Some(json!({"session_label":"reader","auth_profile_id":"fixture","client_generation":1,"requested_scopes":["search:read.public","channels:history"],"redirect_profile_id":"loopback","expected_config_revision":view["config_revision"]}))).await;
    assert_ne!(status, 201);
    assert!(
        !f.path().join("counts.json").exists(),
        "deterministic custody refusal precedes traffic"
    );
}

pub async fn boundaries() {
    let (mut f, t) = failures::unprovisioned().await;
    start_refused(&f).await;
    let value = "x".repeat(8192);
    let (code, metadata) = set(&f, &value, 1).await;
    assert_eq!(code, 200, "{metadata}");
    assert_eq!(
        metadata,
        json!({"profile":"fixture","client_generation":1,"state":"configured"})
    );
    assert_eq!(set(&f, "replacement", 1).await.0, 400);
    assert_ne!(set(&f, "different-generation", 2).await.0, 200);
    let db = pool(&f).await;
    sqlx::query("UPDATE credential_secrets SET sealed_value=X'00'")
        .execute(&db)
        .await
        .unwrap();
    db.close().await;
    start_refused(&f).await;
    orphan_retirement(&f);
    f.stop();
    t.stop();
    println!(
        "protected client max boundary/reveal-never, missing/corrupt before claim, no replacement fallback, orphan retirement"
    );
}

pub async fn wrong_client() {
    let (mut f, t) = failures::unprovisioned().await;
    assert_eq!(set(&f, "valid-but-wrong-client", 1).await.0, 200);
    let created = setup::connect_slack(&f, "wrong-client");
    assert_eq!(setup::authorize(&f, &created, false).await, 400);
    assert_eq!(counts(&f)["bad_client"], 1);
    assert_eq!(counts(&f)["token"], 1);
    assert_eq!(counts(&f)["identity"], Value::Null);
    assert_eq!(
        f.op(&[
            "oauth",
            "account-status",
            "fixture",
            "--label",
            "wrong-client"
        ])["state"],
        "absent"
    );
    f.stop();
    t.stop();
}

async fn pool(f: &Fixture) -> sqlx::SqlitePool {
    sqlx::SqlitePool::connect_with(
        sqlx::sqlite::SqliteConnectOptions::new().filename(f.path().join("state.db")),
    )
    .await
    .unwrap()
}

fn orphan_retirement(f: &Fixture) {
    f.op(&["tool", "delete", "fixture"]);
    let retired = f.op(&[
        "oauth",
        "client",
        "retire",
        "fixture",
        "--profile",
        "fixture",
        "--client-generation",
        "1",
    ]);
    assert_eq!(retired["state"], "retired");
}
