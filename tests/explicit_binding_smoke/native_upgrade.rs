//! Actual pre-0011 state, preserved HTTP receipts and refusal by the old binary.
use super::{fixture::Fixture, migration, process, setup, upstream, workflow};
use serde_json::Value;

pub async fn exercise() {
    let prior = std::env::var("LOCKSMITH_NATIVE_PRIOR_DAEMON").expect("pre-0011 daemon required");
    let old_cli = std::path::Path::new(&prior).with_file_name("locksmith");
    let receiver = upstream::Receiver::start().await;
    let mut f = Fixture::new(&receiver.server.uri());
    let (agents, before) = prepare(&mut f, &receiver, &prior, &old_cli).await;
    f.start().await;
    assert_eq!(sql(&f, "SELECT max(version) FROM _sqlx_migrations;"), "14");
    assert_eq!(authority(&f), before);
    assert_eq!(
        sql(
            &f,
            "SELECT count(*) FROM registrations WHERE protocol != 'http';"
        ),
        "0"
    );
    workflow::shared(&f, &receiver, &agents).await;
    f.stop();
    apply(&f, std::path::Path::new(process::CLI));
    assert_eq!(
        authority(&f),
        before,
        "old reviewed receipt did not remain idempotent"
    );
    refused(&f, &prior);
    restarted(f, &receiver, &agents, &before).await;
    println!(
        "N1 upgrade10->current: HTTP X/X/Y, revoked identities/bootstrap, bindings and actual old receipt unchanged; no native rows; prior refuses before both listeners; restart works"
    );
}
fn sql(f: &Fixture, query: &str) -> String {
    migration::sqlite(f, &f.db, query).trim().into()
}
fn authority(f: &Fixture) -> Vec<String> {
    ["SELECT json_array(id,public_id,name,tool_allowlist,tool_denylist,grants_reviewed,expires_at,revoked_at) FROM agents ORDER BY id;",
     "SELECT json_array(agent_id,registration,auth_spec,created_at,updated_at) FROM agent_credential_overrides ORDER BY agent_id,registration;",
     "SELECT json_array(public_id,scope,grants_reviewed,revoked_at) FROM bootstrap_tokens ORDER BY public_id;",
     "SELECT json_array(key,value) FROM registrations_meta ORDER BY key;"]
        .map(|q|sql(f,q)).into()
}
fn receipt(f: &Fixture, cli: &std::path::Path) {
    let mut c = process::command(cli.to_str().unwrap());
    c.args(["migrate-bindings", "--grants", "preview", "--database"])
        .arg(&f.db);
    let mut plan = process::json(process::run(c));
    for grant in plan["grants"].as_array_mut().unwrap() {
        grant["selected"] = true.into();
    }
    std::fs::write(
        f.path().join("native-receipt.json"),
        serde_json::to_vec(&plan).unwrap(),
    )
    .unwrap();
    apply(f, cli);
}
fn apply(f: &Fixture, cli: &std::path::Path) {
    let mut c = process::command(cli.to_str().unwrap());
    c.args(["migrate-bindings", "apply", "--database"])
        .arg(&f.db)
        .arg("--plan")
        .arg(f.path().join("native-receipt.json"));
    let result: Value = process::json(process::run(c));
    assert_eq!(result["inserted"], 0);
}
fn refused(f: &Fixture, prior: &str) {
    let _ = std::fs::remove_file(&f.socket);
    let mut c = process::command(prior);
    c.arg("--config").arg(&f.config);
    let out = process::run(c);
    assert!(!out.status.success());
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        text.contains("migration 11") && text.contains("missing"),
        "expected native migration refusal"
    );
    assert!(!f.socket.exists());
    assert!(std::net::TcpStream::connect(("127.0.0.1", f.port)).is_err());
}

async fn prepare(
    f: &mut Fixture,
    receiver: &upstream::Receiver,
    prior: &str,
    old_cli: &std::path::Path,
) -> (Vec<setup::Agent>, Vec<String>) {
    f.start_with_env(&[("LOCKSMITHD_BIN", prior)]).await;
    assert_eq!(sql(f, "SELECT max(version) FROM _sqlx_migrations;"), "10");
    let agents = setup::enroll(f).await;
    f.op(&["agent", "revoke", &agents[3].id]);
    let bootstrap = f.op(&["bootstrap", "mint", "--allowlist", "accounts", "--reusable"]);
    f.op(&[
        "bootstrap",
        "revoke",
        bootstrap["public_id"].as_str().unwrap(),
    ]);
    workflow::shared(f, receiver, &agents).await;
    f.stop();
    receipt(f, old_cli);
    let before = authority(f);
    (agents, before)
}

async fn restarted(
    mut f: Fixture,
    receiver: &upstream::Receiver,
    agents: &[setup::Agent],
    before: &[String],
) {
    f.start().await;
    assert_eq!(authority(&f), before);
    workflow::shared(&f, receiver, agents).await;
    f.cleanup();
}
