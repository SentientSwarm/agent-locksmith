use super::fixture::*;
use agent_locksmith::registrations::{AuthSpec, Kind, Registration};
use serde_json::Value;

pub(super) async fn add(f: &Fixture, name: &str, spec: AuthSpec) {
    f.registrations
        .create(&Registration::new(
            name.into(),
            Kind::Tool,
            "test".into(),
            "http://127.0.0.1:1".into(),
            spec,
        ))
        .await
        .unwrap();
}
pub(super) fn row(p: &Value, id: i64, name: &str) -> Value {
    p["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["agent_id"] == id && r["registration"] == name)
        .unwrap()
        .clone()
}
#[tokio::test]
async fn inventory_reuses_deny_wins_and_flags_unavailable_routes() {
    let f = Fixture::new().await;
    unavailable_routes(&f).await;
    let p = f.preview();
    for (id, reason) in [
        (f.ids[0], "in_denylist"),
        (f.ids[1], "agent_revoked"),
        (f.ids[3], "agent_expired"),
    ] {
        assert_eq!(row(&p, id, "api")["reason"], reason);
        assert_eq!(row(&p, id, "api")["action"], "skip");
    }
    assert_eq!(row(&p, f.ids[2], "api")["action"], "preserve");
    assert_eq!(
        row(&p, f.ids[2], "disabled")["reason"],
        "registration_disabled"
    );
    assert_eq!(
        row(&p, f.ids[2], "missing")["reason"],
        "missing_or_tombstoned_stored_source"
    );
    assert_eq!(row(&p, f.ids[2], "file")["action"], "skip");
    assert!(!p.to_string().contains("PRIVATE_FILE_SENTINEL"));
}
#[tokio::test]
async fn legacy_inventory_never_imports_or_exports_file_or_inline_values() {
    let f = Fixture::new().await;
    let config = f.dir.path().join("legacy.yaml");
    let bytes = b"tools:\n  - name: file\n    auth:\n      value:\n        from_file_sealed:\n          path: PRIVATE_FILE_SENTINEL\n  - name: inline\n    auth:\n      value: PRIVATE_INLINE_SENTINEL\n";
    std::fs::write(&config, bytes).unwrap();
    let o = legacy_preview(&f, &config);
    success(&o);
    let p: Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(p["legacy"][0]["name"], "file");
    assert!(
        p["legacy"][0]["reason"]
            .as_str()
            .unwrap()
            .contains("unsupported_file_source")
    );
    assert!(
        p["legacy"][1]["reason"]
            .as_str()
            .unwrap()
            .contains("register_authenticate_agent")
    );
    for private in ["PRIVATE_FILE_SENTINEL", "PRIVATE_INLINE_SENTINEL"] {
        assert!(!String::from_utf8_lossy(&o.stdout).contains(private));
    }
    assert_eq!(std::fs::read(config).unwrap(), bytes);
    assert_eq!(f.count().await, 1);
}

async fn unavailable_routes(f: &Fixture) {
    f.exec("UPDATE agents SET tool_allowlist='[\"api\"]', tool_denylist='[\"api\"]' WHERE name='shared-a'").await;
    f.exec("UPDATE agents SET revoked_at=1 WHERE name='shared-b'")
        .await;
    f.exec("UPDATE agents SET expires_at=1 WHERE name='unmapped'")
        .await;
    add(f, "disabled", env_spec()).await;
    f.exec("UPDATE registrations SET disabled=1 WHERE name='disabled'")
        .await;
    add(
        f,
        "missing",
        AuthSpec::StoredBearer {
            secret_ref: "cs_absent".into(),
        },
    )
    .await;
    f.exec("INSERT INTO registrations (name,kind,upstream,auth_json,timeouts_json,created_at,updated_at) VALUES ('file','tool','http://127.0.0.1:1','{\"kind\":\"from_file_sealed\",\"path\":\"PRIVATE_FILE_SENTINEL\"}','{}',1,1)").await;
}

fn legacy_preview(f: &Fixture, config: &std::path::Path) -> std::process::Output {
    f.command("preview")
        .arg("--legacy-config")
        .arg(config)
        .output()
        .unwrap()
}
