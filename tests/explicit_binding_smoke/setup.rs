use super::{fixture::Fixture, process};
use std::path::Path;

pub struct Agent {
    pub id: String,
    pub token: String,
}
pub fn operator(dir: &Path) -> String {
    let mut c = super::docs::command(super::docs::SETUP, "operator");
    c.env("FIXTURE_DIR", dir);
    let output = process::run(c);
    assert!(output.status.success(), "offline operator bootstrap");
    assert!(
        std::fs::read_to_string(dir.join("operators.yaml"))
            .unwrap()
            .contains("token_hash")
    );
    String::from_utf8(output.stderr)
        .unwrap()
        .lines()
        .map(str::trim)
        .find(|s| s.starts_with("lkop_"))
        .expect("one-time operator token")
        .to_owned()
}
pub fn config(f: &Fixture) {
    let mut value: serde_json::Value =
        serde_yaml::from_str(super::docs::block(super::docs::SETUP, "config")).unwrap();
    value["listen"]["port"] = f.port.into();
    value["listen"]["admin_socket"]["path"] = f.socket.to_str().unwrap().into();
    value["database"]["path"] = f.db.to_str().unwrap().into();
    value["operator_credentials_path"] = f.path().join("operators.yaml").to_str().unwrap().into();
    std::fs::write(&f.config, serde_yaml::to_string(&value).unwrap()).unwrap();
}
pub fn register(f: &Fixture, name: &str) -> Agent {
    let mut c = super::docs::fixture(f, super::docs::SETUP, "register");
    c.env("AGENT_NAME", name).env("ALLOWLIST", "accounts");
    let v = process::json(process::run(c));
    f.tokens
        .borrow_mut()
        .push(v["token"].as_str().unwrap().into());
    Agent {
        id: v["public_id"].as_str().unwrap().into(),
        token: v["token"].as_str().unwrap().into(),
    }
}
pub fn put(f: &Fixture, name: &str, source: &str) {
    let mut c = super::docs::fixture(f, super::docs::SETUP, "catalog");
    c.env("REGISTRATION", name).env("AUTH_SOURCE", source);
    process::json(process::run(c));
}
pub fn bind(f: &Fixture, a: &Agent, source: &str) {
    let mut c = super::docs::fixture(f, super::docs::SETUP, "bind");
    c.env("AGENT_ID", &a.id).env("AUTH_SOURCE", source);
    process::json(process::run(c));
}
pub async fn enroll(f: &Fixture) -> Vec<Agent> {
    version(f).await;
    put(f, "accounts", "bearer=SMOKE_X");
    let agents: Vec<_> = ["shared-a", "shared-b", "distinct-c", "unmapped"]
        .map(|n| register(f, n))
        .into();
    for (a, source) in agents
        .iter()
        .zip(["bearer=SMOKE_X", "bearer=SMOKE_X", "bearer=SMOKE_Y"])
    {
        bind(f, a, source);
    }
    let mut c = super::docs::fixture(f, super::docs::SETUP, "status");
    c.env("LOCKSMITH_AGENT_TOKEN", &agents[0].token);
    assert_eq!(process::json(process::run(c))["name"], "shared-a");
    operator_auth(f);
    agents
}

pub fn clear(f: &Fixture, a: &Agent) {
    let mut c = super::docs::fixture(f, super::docs::SETUP, "clear");
    c.env("AGENT_ID", &a.id);
    process::json(process::run(c));
}

pub fn add_legacy(f: &Fixture) {
    let mut value: serde_json::Value =
        serde_yaml::from_str(&std::fs::read_to_string(&f.config).unwrap()).unwrap();
    value["tools"] = serde_json::json!([{"name":"legacy-prefixed", "description":"owner mapping fixture", "upstream":f.upstream, "egress":"direct",
        "auth":{"header":"Authorization", "value":{"from_env":{"var":"SMOKE_X", "prefix":"Bearer "}}}}]);
    std::fs::write(&f.config, serde_yaml::to_string(&value).unwrap()).unwrap();
}

async fn version(f: &Fixture) {
    let version: serde_json::Value = f
        .http
        .get(f.url("/version"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    if f.prior {
        // A retained prior binary reports its own release, not this one.
        let reported = version["version"].as_str().unwrap_or_default();
        assert!(
            !reported.is_empty() && reported.split('.').all(|p| p.parse::<u32>().is_ok()),
            "prior daemon version is not a release number"
        );
    } else {
        assert_eq!(version["version"], env!("CARGO_PKG_VERSION"));
    }
    println!(
        "SM01 daemon version={}, actual CLI/UDS, loopback synthetic fixture",
        version["version"]
    );
}
fn operator_auth(f: &Fixture) {
    for token in [None, Some("synthetic-invalid-operator")] {
        let mut c = f.cli(&["agent", "list"]);
        c.env_remove("LOCKSMITH_OP_TOKEN");
        if let Some(t) = token {
            c.env("LOCKSMITH_OP_TOKEN", t);
        }
        assert_eq!(process::run(c).status.code(), Some(3));
    }
}
