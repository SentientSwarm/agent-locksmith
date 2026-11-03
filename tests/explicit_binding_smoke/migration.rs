use super::{
    fixture::Fixture,
    process,
    setup::{self, Agent},
    upstream::{self, Receiver},
    workflow,
};
use serde_json::Value;

fn sqlite(f: &Fixture, db: &std::path::Path, sql: &str) -> String {
    assert!(
        db.exists(),
        "missing fixture DB {}",
        db.file_name().unwrap().to_string_lossy()
    );
    let mut c = process::command("sqlite3");
    c.current_dir(f.path()).arg(db).arg(sql);
    let o = process::run(c);
    assert!(
        o.status.success(),
        "sqlite3 {:?} query={sql} db={}: {}",
        o.status.code(),
        db.file_name().unwrap().to_string_lossy(),
        String::from_utf8_lossy(&o.stderr).replace(f.path().to_str().unwrap(), "[fixture]")
    );
    String::from_utf8(o.stdout).unwrap()
}
fn apply(f: &Fixture, code: i32) -> Value {
    assert!(f.daemon.is_none());
    let o = process::run(super::docs::fixture(f, super::docs::UPGRADE, "apply"));
    assert_eq!(o.status.code(), Some(code));
    if code == 0 {
        return process::json(o);
    }
    assert!(String::from_utf8_lossy(&o.stderr).contains("migration_conflict"));
    Value::Null
}
fn preview(f: &Fixture) -> Value {
    let before = std::fs::read(&f.db).unwrap();
    let first = run_preview(f);
    let second = run_preview(f);
    assert_eq!(first, second, "deterministic reference inventory");
    assert_eq!(std::fs::read(&f.db).unwrap(), before, "preview wrote DB");
    let value: Value = serde_json::from_slice(&first).unwrap();
    super::safety::no_values(&serde_json::to_string(&value).unwrap(), &[]);
    std::fs::write(
        f.path().join("bindings-plan.json"),
        serde_json::to_vec_pretty(&value).unwrap(),
    )
    .unwrap();
    value
}
fn review(f: &Fixture, a: &[Agent], mut plan: Value) {
    let wanted: Vec<_> = plan["agents"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|row| a[..2].iter().any(|agent| row["public_id"] == agent.id))
        .map(|row| row["id"].clone())
        .collect();
    select(&mut plan, &wanted);
    let preserved = plan["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["registration"] == "accounts" && e["auth_spec"]["env_var"] == "SMOKE_Y")
        .unwrap();
    assert_eq!(preserved["action"], "preserve");
    std::fs::write(
        f.path().join("bindings-reviewed.json"),
        serde_json::to_vec_pretty(&plan).unwrap(),
    )
    .unwrap();
}
fn stale_and_apply(f: &Fixture) {
    let config = std::fs::read_to_string(&f.config).unwrap();
    let before = sqlite(f, &f.db, "SELECT COUNT(*) FROM agent_credential_overrides;");
    std::fs::write(&f.config, config.replace("SMOKE_X", "SMOKE_Y")).unwrap();
    apply(f, 5);
    assert_eq!(
        sqlite(f, &f.db, "SELECT COUNT(*) FROM agent_credential_overrides;"),
        before
    );
    std::fs::write(&f.config, config).unwrap();
    assert_eq!(apply(f, 0)["inserted"], 2);
    assert_eq!(apply(f, 0)["inserted"], 0);
}
pub async fn cutover(f: &mut Fixture, r: &Receiver, a: &[Agent]) {
    f.stop();
    setup::add_legacy(f);
    f.start().await;
    setup::put(f, "accounts", "bearer=SMOKE_X");
    for agent in &a[..2] {
        setup::clear(f, agent);
    }
    f.stop();
    offline_upgrade(f, a);
    f.start().await;
    workflow::shared(f, r, a).await;
    for route in ["accounts/check", "legacy-prefixed/check"] {
        upstream::denied(f, r, Some(&a[3].token), route, 403, "tool_not_allowed").await;
    }
    no_recreation(f, r, a).await;
    setup::put(f, "future", "bearer=SMOKE_Y");
    upstream::denied(
        f,
        r,
        Some(&a[0].token),
        "future/check",
        403,
        "tool_not_allowed",
    )
    .await;
    println!(
        "SM04 stopped-daemon backup/preview/review/apply=2/repeat=0; real restart X/X/Y; stale/clear/new/owner-mapping zero-dispatch PASS"
    );
}
async fn no_recreation(f: &mut Fixture, r: &Receiver, a: &[Agent]) {
    setup::clear(f, &a[0]);
    f.stop();
    apply(f, 5);
    f.start().await;
    upstream::denied(
        f,
        r,
        Some(&a[0].token),
        "accounts/check",
        403,
        "tool_not_allowed",
    )
    .await;
    setup::bind(f, &a[0], "bearer=SMOKE_X");
    upstream::allowed(f, r, &a[0].token, "accounts/check", "X").await;
}

fn run_preview(f: &Fixture) -> Vec<u8> {
    assert!(f.daemon.is_none());
    let o = process::run(super::docs::fixture(f, super::docs::UPGRADE, "preview"));
    assert!(o.status.success());
    std::fs::read(f.path().join("bindings-plan.json")).unwrap()
}

fn select(plan: &mut Value, wanted: &[Value]) {
    let mut count = 0;
    for row in plan["entries"].as_array_mut().unwrap() {
        if wanted.contains(&row["agent_id"]) && row["registration"] == "accounts" {
            assert_eq!(row["action"], "propose");
            row["selected"] = true.into();
            count += 1;
        } else if wanted.contains(&row["agent_id"]) && row["registration"] == "legacy-prefixed" {
            assert_eq!(
                row["action"], "skip",
                "lossy source must need owner mapping"
            );
        }
    }
    assert_eq!(count, 2);
}

fn offline_upgrade(f: &Fixture, a: &[Agent]) {
    let backup = process::run(super::docs::fixture(f, super::docs::UPGRADE, "backup"));
    assert!(
        backup.status.success(),
        "backup {:?}: {}",
        backup.status.code(),
        String::from_utf8_lossy(&backup.stderr).replace(f.path().to_str().unwrap(), "[fixture]")
    );
    assert_eq!(String::from_utf8(backup.stdout).unwrap().trim(), "ok");
    assert_eq!(
        sqlite(
            f,
            &f.path().join("before-bindings.db"),
            "PRAGMA integrity_check;"
        )
        .trim(),
        "ok"
    );
    review(f, a, preview(f));
    stale_and_apply(f);
}
