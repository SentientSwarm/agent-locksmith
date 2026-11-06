use super::*;

pub async fn categorical() {
    let (mut f, t) = callback_support::ready(true).await;
    let mut cases = optional_cases();
    cases.extend(required_cases());
    cases.extend(nested_cases());
    for (index, (plan, reason)) in cases.iter().enumerate() {
        refused(&f, index, plan, reason).await;
    }
    assert_eq!(counts(&f)["token"], cases.len());
    assert_eq!(counts(&f)["identity"], Value::Null);
    assert_eq!(counts(&f)["tool"], Value::Null);
    no_plaintext(&f);
    f.stop();
    t.stop();
    println!(
        "{} metadata predicates: one response each, zero identity/account/business; joined",
        cases.len()
    );
}

fn optional_cases() -> Vec<(Value, String)> {
    let mut cases = Vec::new();
    for key in [
        "issuer",
        "iss",
        "resource",
        "client_id",
        "scope",
        "team_id",
        "user_id",
    ] {
        let field = if ["scope", "team_id", "user_id"].contains(&key) {
            format!("root_{key}")
        } else {
            key.to_string()
        };
        for (value, suffix) in [
            (Value::Null, "null"),
            (json!([]), "type"),
            (json!("invented-diagnostic-canary"), "mismatch"),
        ] {
            cases.push((
                json!({"path":key,"mode":"set","value":value}),
                format!("slack_token_{field}_{suffix}"),
            ));
        }
    }
    cases
}

fn required_cases() -> Vec<(Value, String)> {
    let mut cases = Vec::new();
    for path in [
        "team",
        "authed_user",
        "team/id",
        "authed_user/id",
        "authed_user/scope",
    ] {
        let field = path.replace('/', "_");
        for (mode, value, suffix) in [
            ("missing", Value::Null, "missing"),
            ("set", Value::Null, "null"),
            ("set", json!([]), "type"),
        ] {
            cases.push((
                json!({"path":path,"mode":mode,"value":value}),
                format!("slack_token_{field}_{suffix}"),
            ));
        }
        if path.contains('/') {
            cases.push((
                json!({"path":path,"mode":"set","value":"invented-diagnostic-canary"}),
                format!("slack_token_{field}_mismatch"),
            ));
        }
    }
    cases
}

fn nested_cases() -> Vec<(Value, String)> {
    let mut cases = Vec::new();
    for key in ["access_token", "refresh_token", "expires_in", "token_type"] {
        for (value, suffix) in [
            (Value::Null, "null"),
            (json!([]), "type"),
            (
                if key == "expires_in" {
                    json!(7)
                } else {
                    json!("invented-diagnostic-canary")
                },
                "conflict",
            ),
        ] {
            cases.push((
                json!({"path":format!("authed_user/{key}"),"mode":"set","value":value}),
                format!("slack_token_nested_{key}_{suffix}"),
            ));
        }
    }
    cases
}

async fn refused(f: &Fixture, index: usize, plan: &Value, reason: &str) {
    std::fs::write(f.path().join("metadata-case.json"), plan.to_string()).unwrap();
    let label = format!("metadata-{index}");
    let attempt = setup::connect_slack(f, &label);
    let raw = setup::issue(f, &attempt, false).await;
    let before = counts(f);
    assert_eq!(
        callback_support::send(f, callback_support::without_issuer(&raw)).await,
        400
    );
    let status = f.op(&[
        "oauth",
        "attempt-status",
        "fixture",
        attempt["attempt_id"].as_str().unwrap(),
    ]);
    assert_eq!(status["state"], "failed");
    assert_eq!(status["stage"], "token");
    assert_eq!(status["safe_reason"], reason);
    assert_eq!(
        f.op(&["oauth", "account-status", "fixture", "--label", &label])["state"],
        "absent"
    );
    assert_eq!(
        counts(f)["token"].as_u64().unwrap(),
        before["token"].as_u64().unwrap_or(0) + 1
    );
    assert_eq!(counts(f)["identity"], before["identity"]);
    assert!(!status.to_string().contains("canary"));
}

fn no_plaintext(f: &Fixture) {
    for file in ["daemon.log", "state.db", "state.db-wal"] {
        if let Ok(bytes) = std::fs::read(f.path().join(file)) {
            for secret in [
                "invented-diagnostic-canary",
                "invented-access-1",
                "invented-refresh-1",
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

pub async fn bounds() {
    let (mut f, t) = callback_support::ready(true).await;
    for (index, (raw, reason)) in [
        (r#"{"ok":true,"ok":true}"#.to_owned(), "json_refused"),
        (
            r#"{"team":{"id":"a","\u0069d":"b"}}"#.to_owned(),
            "json_refused",
        ),
        (" ".repeat(65537), "token_body_limit"),
        (
            format!("{}0{}", "[".repeat(40), "]".repeat(40)),
            "json_refused",
        ),
    ]
    .into_iter()
    .enumerate()
    {
        refused(&f, index, &json!({"raw":raw}), reason).await;
    }
    metadata_refresh::exact_body_limit(&f).await;
    no_plaintext(&f);
    f.stop();
    t.stop();
}
