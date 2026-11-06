use super::*;

pub async fn journey() {
    let (mut f, t) = ready().await;
    setup::promote(&f, &t);
    setup::provision(&f);
    let created = setup::connect_slack(&f, "reader");
    assert_eq!(setup::authorize(&f, &created, false).await, 200);
    let agent = f.op(&[
        "agent",
        "register",
        "--name",
        "resource-reader",
        "--allowlist",
        "fixture",
    ]);
    receiving::select(&f, &agent);
    denials::denied_tools(&f, &agent).await;
    receiving::prepare(&f, &agent).await;
    receiving::use_both(&f, &agent).await;
    assert_eq!(counts(&f)["tool"], 4);
    refresh_restart(&mut f, &agent).await;
    assert!(counts(&f)["transport-delete"].as_u64().unwrap() > 0);
    assert_eq!(counts(&f)["matched_verifier"], 1);
    assert_eq!(counts(&f)["refresh"], 1);
    f.stop();
    t.stop();
    println!(
        "canonical resource on authorization/code/refresh; promoted /mcp POST/DELETE; both facades8 effects; joined restart"
    );
}

pub(super) async fn ready() -> (Fixture, Twin) {
    let mut f = Fixture::new();
    std::fs::write(f.path().join("separate-resource"), "invented").unwrap();
    let t = Twin::script(
        &f,
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/oauth_consent/slack/provider.py"
        ),
    );
    setup::configure_slack(&f, &t);
    let path = f.path().join("config.yaml");
    let mut config: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    config["oauth_consent"]["profiles"][0]["resource"] = json!(t.url(""));
    std::fs::write(&path, config.to_string()).unwrap();
    f.start_with_keys(
        process::DAEMON,
        Some("AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI="),
        Some(KEY),
    )
    .await;
    (f, t)
}
