use super::*;

pub(super) fn configure_slack(f: &Fixture, t: &Twin) {
    configure(f, t);
    let path = f.path().join("config.yaml");
    let mut c: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let p = &mut c["oauth_consent"]["profiles"][0];
    p["kind"] = json!("slack-confidential-fixture-v1");
    p["authorization_endpoint"] = json!(t.url("/oauth/v2_user/authorize"));
    p["token_endpoint"] = json!(t.url("/api/oauth.v2.user.access"));
    p["resource"] = json!(t.url("/mcp"));
    p["expected_workspace"] = json!("TTEST001");
    p["expected_user"] = json!("UTEST001");
    std::fs::write(path, c.to_string()).unwrap();
}

pub(super) fn promote(f: &Fixture, t: &Twin) {
    create(f, &t.url("/mcp"));
    activate(f);
}

pub(super) fn create(f: &Fixture, upstream: &str) {
    import(f);
    f.op(&[
        "tool",
        "from-definition",
        "fixture",
        "--definition",
        "local.slack-fixture",
        "--revision",
        "1",
        "--auth-profile",
        "controlled",
        "--upstream",
        upstream,
        "--allow-private-destination",
    ]);
}

fn activate(f: &Fixture) {
    let before = f.op(&["tool", "get", "fixture"]);
    f.op(&[
        "tool",
        "activate-definition",
        "fixture",
        "--if-match",
        before["definition_control"]["revision"].as_str().unwrap(),
        "--compact",
        "--oauth-profile",
        "fixture",
        "--contract-policy",
        "finite-v2",
        "--selected-tool",
        "search_messages",
        "--selected-tool",
        "read_thread",
    ]);
    assert!(
        !f.path().join("counts.json").exists(),
        "promotion produces zero upstream traffic"
    );
}

pub(super) fn provision(f: &Fixture) {
    let mut input = tempfile::tempfile().unwrap();
    use std::io::{Seek, Write};
    input.write_all(b"invented-client-secret\n").unwrap();
    input.rewind().unwrap();
    let mut command = f.command(&[
        "oauth",
        "client",
        "set",
        "fixture",
        "--profile",
        "fixture",
        "--client-generation",
        "1",
        "--secret-stdin",
    ]);
    command.stdin(Stdio::from(input));
    let result = process::json(process::run(command));
    assert_eq!(result["state"], "configured");
    assert!(!result.to_string().contains("invented-client-secret"));
    check_client_status(f, &result);
}

fn check_client_status(f: &Fixture, result: &Value) {
    let status = f.op(&[
        "oauth",
        "client",
        "status",
        "fixture",
        "--profile",
        "fixture",
        "--client-generation",
        "1",
    ]);
    assert_eq!(&status, result);
}

pub(super) fn connect_slack(f: &Fixture, label: &str) -> Value {
    let status = f.op(&["oauth", "account-status", "fixture", "--label", label]);
    f.op(&[
        "oauth",
        "connect",
        "fixture",
        "--label",
        label,
        "--profile",
        "fixture",
        "--client-generation",
        "1",
        "--redirect-profile",
        "loopback",
        "--expected-config-revision",
        &status["config_revision"].to_string(),
        "--scopes",
        "search:read.public,channels:history",
    ])
}

pub(super) async fn authorize(f: &Fixture, created: &Value, wrong: bool) -> u16 {
    f.http
        .get(issue(f, created, wrong).await)
        .timeout(Duration::from_secs(45))
        .send()
        .await
        .unwrap()
        .status()
        .as_u16()
}

pub(super) async fn issue(f: &Fixture, created: &Value, wrong: bool) -> String {
    let mut url = reqwest::Url::parse(created["authorization_url"].as_str().unwrap()).unwrap();
    if wrong {
        wrong_challenge(&mut url);
    }
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .add_root_certificate(reqwest::Certificate::from_pem(f.pki.ca.as_bytes()).unwrap())
        .build()
        .unwrap();
    let issued = client.get(url).send().await.unwrap();
    assert_eq!(issued.status(), 302);
    issued.headers()["location"].to_str().unwrap().to_owned()
}

fn wrong_challenge(url: &mut reqwest::Url) {
    use base64::Engine;
    use sha2::{Digest, Sha256};
    {
        let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(
            b"a-different-valid-verifier-of-at-least-43-characters",
        ));
        let query = url
            .query_pairs()
            .map(|(k, v)| {
                (
                    k.to_string(),
                    if k == "code_challenge" {
                        challenge.clone()
                    } else {
                        v.to_string()
                    },
                )
            })
            .collect::<Vec<_>>();
        url.set_query(None);
        url.query_pairs_mut().extend_pairs(query);
    }
}

fn import(f: &Fixture) {
    let mut d: Value = serde_json::from_str(include_str!(
        "../../../definitions/customer-controlled.example.json"
    ))
    .unwrap();
    d["id"] = json!("local.slack-fixture");
    d["auth_profiles"][0]["required_scopes"] = json!(["search:read.public", "channels:history"]);
    let path = f.path().join("definition.json");
    std::fs::write(&path, d.to_string()).unwrap();
    f.op(&["integration", "import", "--file", path.to_str().unwrap()]);
}
