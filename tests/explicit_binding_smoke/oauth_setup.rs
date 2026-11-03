use super::{fixture::Fixture, oauth_provider::Provider, process, setup};
use agent_locksmith::admin::uds_client::UdsClient;
use serde_json::{Value, json};

// Synthetic fixture key only; process::command clears the real environment.
pub const KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
pub const ENV: &[(&str, &str)] = &[("LOCKSMITH_OAUTH_SEALING_KEY", KEY)];

pub async fn enroll(f: &Fixture, provider: &Provider) -> setup::Agent {
    let auth = json!({"kind":"oauth_device_code", "client_id":"fixture-client",
        "scopes":[], "device_url":format!("{}/device", provider.url),
        "token_url":format!("{}/token", provider.url), "session_label":"reader"});
    put(
        f,
        "/admin/operator/tools/accounts",
        json!({"description":"OAuth fixture",
        "upstream":f.upstream, "egress":"direct", "auth":auth}),
    )
    .await;
    let agent = setup::register(f, "oauth-reader");
    put(
        f,
        &format!("/admin/operator/agents/{}/credentials/accounts", agent.id),
        json!({"auth_spec":auth}),
    )
    .await;
    agent
}
async fn put(f: &Fixture, path: &str, body: Value) {
    let (status, _) = UdsClient::new(&f.socket)
        .request(
            "PUT",
            path,
            &[
                ("authorization", &format!("Bearer {}", f.operator)),
                ("content-type", "application/json"),
            ],
            Some(serde_json::to_vec(&body).unwrap()),
        )
        .await
        .unwrap();
    assert!(
        (200..300).contains(&status),
        "operator setup status {status}"
    );
}
pub fn bootstrap(f: &Fixture) -> std::process::Command {
    f.cli(&[
        "oauth",
        "bootstrap",
        "accounts",
        "--label",
        "reader",
        "--refresh-token",
        "synthetic-bootstrap-refresh",
    ])
}
pub fn connect(f: &Fixture) {
    assert!(
        process::run(bootstrap(f)).status.success(),
        "replacement bootstrap"
    );
}
pub fn revoke(f: &Fixture) {
    f.op(&["oauth", "revoke", "accounts", "--label", "reader"]);
    assert_eq!(
        f.op(&["oauth", "status", "accounts", "--label", "reader"])["present"],
        false
    );
}
pub fn authority(f: &Fixture, agent: &setup::Agent) -> Vec<Value> {
    let mut row = f.op(&["agent", "get", &agent.id]);
    // Authentication updates activity; it must not change authority or bindings.
    row.as_object_mut().unwrap().remove("last_used_at");
    vec![row, f.op(&["agent", "credentials", "list", &agent.id])]
}

pub fn safe_reads(f: &Fixture) {
    let audit = f.op(&["audit", "query", "--tool", "accounts", "--limit", "1000"]);
    let status = f.op(&["oauth", "status", "accounts", "--label", "reader"]);
    safe(&audit.to_string());
    safe(&status.to_string());
    for n in 0..f.starts {
        safe(&std::fs::read_to_string(f.path().join(format!("daemon-{n}.log"))).unwrap());
    }
}
pub fn safe(text: &str) {
    super::safety::no_values(
        text,
        &["synthetic-bootstrap-refresh", "synthetic-rotated-refresh"],
    );
}
