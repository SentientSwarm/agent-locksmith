use super::*;
use std::{io::Write, process::Stdio};
pub(super) async fn run(bearer: bool) {
    let mut f = fixture::Fixture::new();
    receiver::configure(&f);
    let up = receiver::Receiver::start(&f);
    write(&f, "manifest.json", tools());
    std::fs::write(f.path().join("policy-record-arguments"), "").unwrap();
    config(&f, Some("finite-v2"));
    f.start_with_key(
        process::DAEMON,
        Some("AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="),
    )
    .await;
    let a = f.enroll(
        "policy-customer",
        &format!("https://localhost:{}/mcp", up.port),
    );
    let id = a["public_id"].as_str().unwrap();
    let t = a["token"].as_str().unwrap();
    if bearer {
        select_bearer(&f, id);
    }
    before_grant(&f, t).await;
    grant_policy(&f, id);
    standard(&f, t).await;
    compact(&f, t).await;
    check_effects(&f, bearer);
    reset(&f, id, up.port);
    f.stop();
    up.stop();
}
fn select_bearer(f: &fixture::Fixture, id: &str) {
    let mut c = f.command(&[
        "agent",
        "set-credential",
        id,
        "native",
        "--stored-bearer-stdin",
    ]);
    c.stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut child = process::Guard(c.spawn().unwrap());
    child
        .0
        .stdin
        .take()
        .unwrap()
        .write_all(b"fixture-account-x")
        .unwrap();
    assert!(process::wait(&mut child.0).success());
}
async fn before_grant(f: &fixture::Fixture, t: &str) {
    let early = wire::open(f, t).await;
    let list = parse(
        wire::post(
            f,
            t,
            Some(&early),
            json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}),
        )
        .await,
    )
    .await;
    assert_eq!(list["result"]["tools"], json!([]));
}
fn check_effects(f: &fixture::Fixture, bearer: bool) {
    let effects = effects(f);
    assert_eq!(effects.len(), 8);
    for (i, e) in effects.iter().enumerate() {
        assert_eq!(e["account"], if bearer { "X" } else { "None" });
        assert_eq!(e["committed"], i + 1);
    }
    assert_eq!(
        effects
            .iter()
            .filter(|e| e["arguments"] == json!({}))
            .count(),
        7
    );
    assert_eq!(
        effects
            .iter()
            .filter(|e| e["arguments"] == json!({"key":"choice-44","flag":true}))
            .count(),
        1
    );
}
fn reset(f: &fixture::Fixture, id: &str, port: u16) {
    config(f, None);
    put(f, port);
    f.op(&["agent", "modify", id, "--allowlist", "native"]);
    f.op(&["agent", "set-credential", id, "native", "--no-auth"]);
    flow::refuse_observe(f, id);
    assert_eq!(flow::show(f, id)["callable"], false);
    assert_eq!(effects(f).len(), 8);
}
