use super::{
    fixture::Fixture,
    process,
    setup::Agent,
    upstream::{X, Y},
};

pub fn no_values(text: &str, tokens: &[&str]) {
    for value in [X, Y, "synthetic-caller-key"]
        .into_iter()
        .chain(tokens.iter().copied())
    {
        assert!(
            !text.contains(value),
            "synthetic private value leaked; content withheld"
        );
    }
    assert!(!text.contains("token_hash"), "authentication hash leaked");
}
pub async fn verify(f: &Fixture, agents: &[Agent]) {
    let saved_tokens = f.tokens.borrow().clone();
    let mut tokens: Vec<_> = saved_tokens.iter().map(String::as_str).collect();
    tokens.push(&f.operator);
    for agent in agents {
        let mut c = super::docs::fixture(f, super::docs::SETUP, "list");
        c.env("AGENT_ID", &agent.id);
        let v = process::json(process::run(c));
        no_values(&v.to_string(), &tokens);
    }
    let audit = f.op(&["audit", "query", "--tool", "accounts", "--limit", "1000"]);
    no_values(&audit.to_string(), &tokens);
    let rows = audit.as_array().expect("audit rows");
    assert!(
        rows.iter()
            .any(|v| v["details"]["auth_source"] == "agent_override")
    );
    assert!(rows.iter().any(|v| v["decision"] == "denied"));
    operational_logs(f, &tokens).await;
    for n in 0..f.starts {
        no_values(
            &std::fs::read_to_string(f.path().join(format!("daemon-{n}.log"))).unwrap(),
            &tokens,
        );
    }
    help();
    println!(
        "SM05 executed bootstrap/config/register/catalog/bind/status/read/audit/upgrade examples; safe reads/logs and CLI help PASS"
    );
}
fn help() {
    for args in [
        vec!["--help"],
        vec!["bootstrap-operator", "--help"],
        vec!["tool", "put", "--help"],
        vec!["agent", "set-credential", "--help"],
        vec!["migrate-bindings", "preview", "--help"],
        vec!["migrate-bindings", "apply", "--help"],
    ] {
        let mut c = process::command(process::CLI);
        c.args(args);
        assert!(process::run(c).status.success());
    }
    let mut c = process::command(process::CLI);
    c.args(["agent", "unset-credential", "--help"]);
    let o = process::run(c);
    assert!(o.status.success());
    let help = String::from_utf8(o.stdout).unwrap();
    assert!(help.contains("denied") && !help.contains("registration default"));
}

async fn operational_logs(f: &Fixture, tokens: &[&str]) {
    let client = agent_locksmith::admin::uds_client::UdsClient::new(&f.socket);
    let (status, logs) = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        client.request(
            "GET",
            "/admin/operator/logs",
            &[("authorization", &format!("Bearer {}", f.operator))],
            None,
        ),
    )
    .await
    .expect("operational-log deadline")
    .unwrap();
    assert_eq!(status, 200);
    no_values(&String::from_utf8_lossy(&logs), tokens);
}
