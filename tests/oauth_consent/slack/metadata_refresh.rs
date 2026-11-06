use super::*;

pub async fn immediate_reason() {
    let (mut f, t) = lifecycle::connected().await;
    std::fs::write(
        f.path().join("metadata-case.json"),
        json!({"path":"team/id","mode":"set","value":"invented-diagnostic-canary"}).to_string(),
    )
    .unwrap();
    let (status, result) = refresh_response(&f).await;
    assert_eq!(status, 400);
    assert_eq!(result["error"]["code"], "slack_token_team_id_mismatch");
    assert_eq!(
        result["refresh"]["safe_reason"],
        "slack_token_team_id_mismatch"
    );
    assert_eq!(result["refresh"]["stage"], "token");
    assert!(!result.to_string().contains("canary"));
    let view = f.op(&["oauth", "account-status", "fixture", "--label", "reader"]);
    assert_eq!(view["refresh_pending"], true);
    assert!(view.get("safe_reason").is_none());
    assert_eq!(counts(&f)["refresh"], 1);
    assert_eq!(counts(&f)["identity"], 1, "only original consent identity");
    assert_eq!(counts(&f)["tool"], Value::Null);
    let before = counts(&f);
    assert!(!process::run(lifecycle::refresh(&f)).status.success());
    assert_eq!(counts(&f), before, "pending cannot retry");
    f.stop();
    t.stop();
}

async fn refresh_response(f: &Fixture) -> (u16, Value) {
    let before = f.op(&["oauth", "account-status", "fixture", "--label", "reader"]);
    let (status, bytes) = UdsClient::new(f.path().join("admin.sock"))
        .request(
            "POST",
            "/admin/operator/tools/fixture/oauth/accounts/reader/refresh",
            &[
                ("authorization", &format!("Bearer {}", f.operator)),
                ("if-match", before["revision"].as_str().unwrap()),
            ],
            None,
        )
        .await
        .unwrap();
    (status, serde_json::from_slice(&bytes).unwrap())
}

pub(super) async fn exact_body_limit(f: &Fixture) {
    std::fs::write(
        f.path().join("metadata-case.json"),
        json!({"pad":65536}).to_string(),
    )
    .unwrap();
    let attempt = setup::connect_slack(f, "exact-body");
    let raw = setup::issue(f, &attempt, false).await;
    assert_eq!(
        callback_support::send(f, callback_support::without_issuer(&raw)).await,
        200
    );
    assert_eq!(
        f.op(&[
            "oauth",
            "account-status",
            "fixture",
            "--label",
            "exact-body"
        ])["state"],
        "connected_unbound"
    );
    assert_eq!(counts(f)["identity"], 1);
}
