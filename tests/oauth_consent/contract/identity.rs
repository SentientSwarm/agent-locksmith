use super::*;

pub async fn run() {
    let (mut f, t) = journey::ready(false, true, false).await;
    let cases = cases();
    for (index, (plan, reason)) in cases.iter().enumerate() {
        refused(&f, index, plan, reason).await;
    }
    std::fs::remove_file(f.path().join("identity-case.json")).unwrap();
    refresh_refusal(&f).await;
    no_plaintext(&f);
    assert_eq!(counts(&f)["tool"], Value::Null);
    f.stop();
    t.stop();
    println!(
        "{} identity refusals plus documented positive/refresh refusal: exact safe reasons, one token/identity per attempt, zero business, joined",
        cases.len()
    );
}
fn cases() -> Vec<(Value, &'static str)> {
    let mut cases = transport_cases();
    cases.extend(vec![
        (
            json!({"set":{"error":"private-identity-canary"}}),
            "identity_error_present",
        ),
        (json!({"set":{"ok":false}}), "identity_ok_refused"),
        (json!({"set":{"team":null}}), "identity_team_display_type"),
        (
            json!({"set":{"team":{"id":"workspace-invented"}}}),
            "identity_team_display_type",
        ),
        (json!({"set":{"team_id":"wrong"}}), "identity_echo_refused"),
        (json!({"set":{"user_id":null}}), "identity_echo_refused"),
        (
            json!({"set":{"bot_id":"invented-bot"}}),
            "identity_echo_refused",
        ),
        (json!({"set":{"is_bot":true}}), "identity_echo_refused"),
        (
            json!({"set":{"issuer":"private-identity-canary"}}),
            "identity_metadata_refused",
        ),
        (json!({"remove":["team_id"]}), "identity_workspace_missing"),
        (json!({"remove":["user_id"]}), "identity_user_missing"),
        (json!({"set":{"extra":"contract-access-1"}}), "secret_echo"),
    ]);
    cases
}
async fn refused(f: &Fixture, index: usize, plan: &Value, reason: &str) {
    std::fs::write(f.path().join("identity-case.json"), plan.to_string()).unwrap();
    let label = format!("identity-{index}");
    let attempt = setup::connect_contract(f, &label);
    let before = prior_counts(f);
    assert_eq!(slack::setup::authorize(f, &attempt, false).await, 400);
    let status = f.op(&[
        "oauth",
        "attempt-status",
        "fixture",
        attempt["attempt_id"].as_str().unwrap(),
    ]);
    assert_eq!(status["state"], "failed");
    assert_eq!(status["stage"], "identity");
    assert_eq!(status["safe_reason"], reason);
    assert!(!status.to_string().contains("canary"));
    assert_eq!(
        f.op(&["oauth", "account-status", "fixture", "--label", &label])["state"],
        "absent"
    );
    for key in ["token", "identity"] {
        assert_eq!(
            counts(f)[key].as_u64().unwrap(),
            before[key].as_u64().unwrap_or(0) + 1
        );
    }
}
async fn refresh_refusal(f: &Fixture) {
    let attempt = setup::connect_contract(f, "reader");
    assert_eq!(slack::setup::authorize(f, &attempt, false).await, 200);
    let before = f.op(&["oauth", "account-status", "fixture", "--label", "reader"]);
    std::fs::write(
        f.path().join("identity-case.json"),
        json!({"remove":["user_id"]}).to_string(),
    )
    .unwrap();
    let (status, value) = refresh_response(f, before["revision"].as_str().unwrap()).await;
    assert_eq!(status, 400);
    assert_eq!(value["refresh"]["safe_reason"], "identity_user_missing");
    assert_eq!(value["error"]["code"], "identity_user_missing");
    let after = f.op(&["oauth", "account-status", "fixture", "--label", "reader"]);
    assert_eq!(after["refresh_pending"], true);
    assert_eq!(after["verified_subject"], before["verified_subject"]);
}
fn no_plaintext(f: &Fixture) {
    for file in ["daemon.log", "state.db", "state.db-wal"] {
        if let Ok(bytes) = std::fs::read(f.path().join(file)) {
            for secret in [
                "private-identity-canary",
                "contract-access-1",
                "contract-refresh-1",
                "invented-client-secret",
            ] {
                assert!(
                    !bytes.windows(secret.len()).any(|w| w == secret.as_bytes()),
                    "plaintext in {file}"
                );
            }
        }
    }
}

fn transport_cases() -> Vec<(Value, &'static str)> {
    vec![
        (json!({"http":401}), "identity_http_refused"),
        (json!({"raw":" ".repeat(65537)}), "identity_body_limit"),
        (json!({"raw":"{\"ok\":true,\"ok\":true}"}), "json_refused"),
        (json!({"raw":"[]"}), "identity_response_shape"),
    ]
}

fn prior_counts(f: &Fixture) -> Value {
    if f.path().join("counts.json").exists() {
        counts(f)
    } else {
        json!({})
    }
}
async fn refresh_response(f: &Fixture, revision: &str) -> (u16, Value) {
    let (status, bytes) = UdsClient::new(f.path().join("admin.sock"))
        .request(
            "POST",
            "/admin/operator/tools/fixture/oauth/accounts/reader/refresh",
            &[
                ("authorization", &format!("Bearer {}", f.operator)),
                ("if-match", revision),
            ],
            None,
        )
        .await
        .unwrap();
    (status, serde_json::from_slice(&bytes).unwrap())
}
