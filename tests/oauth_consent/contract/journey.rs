use super::*;

pub async fn journey(service: bool, slack: bool, nested: bool) {
    let (mut f, t) = ready(service, slack, nested).await;
    let created = setup::connect_contract(&f, "reader");
    assert_eq!(slack::setup::authorize(&f, &created, false).await, 200);
    verify(&f, service).await;
    let agent = f.op(&[
        "agent",
        "register",
        "--name",
        "contract-reader",
        "--allowlist",
        "fixture",
    ]);
    slack::receiving::select(&f, &agent);
    slack::receiving::prepare(&f, &agent).await;
    slack::receiving::use_both(&f, &agent).await;
    refresh_restart(&mut f, &agent, service).await;
    denied_identity(&f).await;
    assert_eq!(counts(&f)["tool"], 8);
    f.stop();
    t.stop();
    println!(
        "declared contract service={service} slack={slack} nested={nested}: actual promotion, consent, typed subject,8 effects, refresh/restart, identity refusal; joined"
    );
}
async fn verify(f: &Fixture, service: bool) {
    let view = f.op(&["oauth", "account-status", "fixture", "--label", "reader"]);
    assert_eq!(view["state"], "connected_unbound");
    assert_eq!(view["kind"], "custom_oauth_v1");
    assert_eq!(
        view["requested_scopes"],
        json!(["catalog:inspect", "records:read"])
    );
    assert_eq!(view["granted_scope"], "catalog:inspect records:read");
    assert_eq!(
        view["verified_subject"]["kind"],
        if service {
            "service_principal"
        } else {
            "user_workspace"
        }
    );
    verify_custody(f, service, &view).await;
}
async fn refresh_restart(f: &mut Fixture, agent: &Value, service: bool) {
    let before = f.op(&["oauth", "account-status", "fixture", "--label", "reader"]);
    f.op(&[
        "oauth",
        "refresh",
        "fixture",
        "--label",
        "reader",
        "--if-match",
        before["revision"].as_str().unwrap(),
    ]);
    assert_eq!(counts(f)["refresh"], 1);
    f.stop();
    f.start_with_keys(
        process::DAEMON,
        Some("AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI="),
        Some(KEY),
    )
    .await;
    verify(f, service).await;
    slack::receiving::prepare(f, agent).await;
    slack::receiving::use_both(f, agent).await;
}
async fn denied_identity(f: &Fixture) {
    std::fs::write(f.path().join("wrong-identity"), "wrong").unwrap();
    let before = counts(f);
    let created = setup::connect_contract(f, "denied");
    assert_eq!(slack::setup::authorize(f, &created, false).await, 400);
    assert_eq!(
        f.op(&["oauth", "account-status", "fixture", "--label", "denied"])["state"],
        "absent"
    );
    assert_eq!(
        counts(f)["token"].as_u64(),
        before["token"].as_u64().map(|n| n + 1)
    );
    assert_eq!(
        counts(f)["identity"].as_u64(),
        before["identity"].as_u64().map(|n| n + 1)
    );
    assert_eq!(counts(f)["tool"], before["tool"]);
}

pub(super) async fn ready(service: bool, slack: bool, nested: bool) -> (Fixture, Twin) {
    let mut f = Fixture::new();
    let t = Twin::script(
        &f,
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/oauth_consent/contract/provider.py"
        ),
    );
    setup::configure_contract(&f, &t, service, slack);
    if nested {
        std::fs::write(f.path().join("nested"), "invented").unwrap();
    }
    f.start_with_keys(
        process::DAEMON,
        Some("AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI="),
        Some(KEY),
    )
    .await;
    setup::promote(&f, &t);
    if !service {
        slack::setup::provision(&f);
    }
    (f, t)
}

async fn verify_custody(f: &Fixture, service: bool, view: &Value) {
    let db = sqlx::SqlitePool::connect(&format!("sqlite:{}", f.path().join("state.db").display()))
        .await
        .unwrap();
    let row: (Option<String>, Option<String>, String) = sqlx::query_as(
        "SELECT workspace_id,user_id,subject_json FROM oauth_sessions WHERE session_label='reader'",
    )
    .fetch_one(&db)
    .await
    .unwrap();
    assert_eq!(row.0.is_none(), service);
    assert_eq!(row.1.is_none(), service);
    assert_eq!(
        serde_json::from_str::<Value>(&row.2).unwrap(),
        view["verified_subject"]
    );
    db.close().await;
}
