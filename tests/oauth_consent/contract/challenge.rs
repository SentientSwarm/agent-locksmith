use super::*;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;

pub(super) fn adapt(f: &Fixture, created: &Value, label: &str) -> String {
    let url = reqwest::Url::parse(created["authorization_url"].as_str().unwrap()).unwrap();
    let q = url
        .query_pairs()
        .collect::<std::collections::HashMap<_, _>>();
    let config: Value =
        serde_json::from_slice(&std::fs::read(f.path().join("config.yaml")).unwrap()).unwrap();
    let p = &config["oauth_consent"]["profiles"][0];
    let expected = json!({"authorization_endpoint":p["authorization_endpoint"],"client_id":p["client_id"],
        "redirect_uri":p["redirect_uri"],"scope":"catalog:inspect records:read","resource":p["resource"],
        "state":q["state"],"code_challenge":q["code_challenge"]});
    std::fs::write(
        f.path().join("original-challenge"),
        q["code_challenge"].as_bytes(),
    )
    .unwrap();
    run_adapter(f, created, label, &expected)
}
fn run_adapter(f: &Fixture, created: &Value, label: &str, expected: &Value) -> String {
    // The helper requires an owner-only parent; the fixture directory's
    // mode follows the process umask, so use a dedicated 0700 directory.
    let private = f.path().join(format!("{label}-challenge"));
    std::fs::create_dir(&private).unwrap();
    std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o700)).unwrap();
    let input = private.join("input.json");
    let output = private.join("output.json");
    std::fs::write(
        &input,
        json!({"url":created["authorization_url"],"expected":expected}).to_string(),
    )
    .unwrap();
    std::fs::set_permissions(&input, std::fs::Permissions::from_mode(0o600)).unwrap();
    let mut command = Command::new("python3");
    command.args([
        "-B",
        concat!(env!("CARGO_MANIFEST_DIR"), "/scripts/oauth-challenge.py"),
        "--input",
        input.to_str().unwrap(),
        "--output",
        output.to_str().unwrap(),
    ]);
    assert_eq!(
        process::json(process::run(command))["state"],
        "challenge_changed"
    );
    let changed: Value = serde_json::from_slice(&std::fs::read(output).unwrap()).unwrap();
    changed["url"].as_str().unwrap().to_owned()
}
pub(super) async fn issue(f: &Fixture, url: &str) -> String {
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .add_root_certificate(reqwest::Certificate::from_pem(f.pki.ca.as_bytes()).unwrap())
        .build()
        .unwrap();
    let reply = client.get(url).send().await.unwrap();
    assert_eq!(reply.status(), 302);
    reply.headers()["location"].to_str().unwrap().to_owned()
}
