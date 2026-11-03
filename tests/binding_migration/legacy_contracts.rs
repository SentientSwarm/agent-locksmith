use super::{fixture::*, inventory::row};
use agent_locksmith::registrations::AuthSpec;
use serde_json::{Value, json};
use std::path::{Path, PathBuf};

pub(super) fn yaml(header: &str, env: &str, prefix: Option<&str>) -> Value {
    json!({"tools":[{"name":"api","auth":{"header":header,"value":{"from_env":{"var":env,"prefix":prefix}}}}]})
}
pub(super) fn write(f: &Fixture, value: &Value) -> PathBuf {
    let p = f.dir.path().join("supplied.yaml");
    std::fs::write(&p, serde_yaml::to_string(value).unwrap()).unwrap();
    p
}
pub(super) fn preview(f: &Fixture, path: &Path) -> Value {
    let o = f
        .command("preview")
        .arg("--legacy-config")
        .arg(path)
        .output()
        .unwrap();
    success(&o);
    serde_json::from_slice(&o.stdout).unwrap()
}
pub(super) fn apply(f: &Fixture, plan: &Value, path: &Path) -> std::process::Output {
    let p = f.dir.path().join("reviewed-legacy.json");
    std::fs::write(&p, serde_json::to_vec(plan).unwrap()).unwrap();
    f.command("apply")
        .arg("--plan")
        .arg(p)
        .arg("--legacy-config")
        .arg(path)
        .output()
        .unwrap()
}
pub(super) async fn header_registration(f: &Fixture) {
    let mut r = f.registrations.get("api").await.unwrap().unwrap();
    r.auth = AuthSpec::Header {
        header: "x-api-key".into(),
        env_var: "MIGRATION_X".into(),
    };
    f.registrations.upsert(&r).await.unwrap();
}
#[tokio::test]
async fn supplied_raw_env_metadata_matches_and_preserves_explicit_choices() {
    let f = Fixture::new().await;
    header_registration(&f).await;
    let path = write(&f, &yaml("X-API-Key", "MIGRATION_X", None));
    let mut p = preview(&f, &path);
    assert_eq!(p, preview(&f, &path));
    assert_eq!(p["legacy"][0]["reference"]["env_var"], "MIGRATION_X");
    select(&mut p, f.ids[0]);
    success(&apply(&f, &p, &path));
    assert_eq!(
        serde_json::from_slice::<Value>(&apply(&f, &p, &path).stdout).unwrap()["inserted"],
        0
    );
    assert_eq!(f.count().await, 2);
    assert_eq!(
        f.bindings
            .get(f.ids[2], "api")
            .await
            .unwrap()
            .unwrap()
            .auth_spec,
        AuthSpec::Bearer {
            env_var: "MIGRATION_Y".into()
        }
    );
}
#[tokio::test]
async fn supplied_env_reference_header_shape_or_omission_refuses_stale_review() {
    for changed in [
        yaml("x-api-key", "MIGRATION_Y", None),
        yaml("x-different", "MIGRATION_X", None),
        yaml("x-api-key", "MIGRATION_X", Some("PRIVATE_PREFIX_SENTINEL")),
    ] {
        let f = Fixture::new().await;
        header_registration(&f).await;
        let path = write(&f, &yaml("x-api-key", "MIGRATION_X", None));
        let mut p = preview(&f, &path);
        select(&mut p, f.ids[0]);
        write(&f, &changed);
        conflict(&apply(&f, &p, &path));
        assert_eq!(f.count().await, 1);
        conflict(&f.apply(&p)); // Omitting previously supplied metadata cannot bypass review.
    }
}
#[tokio::test]
async fn prefixed_and_legacy_string_sources_are_owner_mapping_only_without_literal_export() {
    let mut string = yaml("x-api-key", "MIGRATION_X", None);
    string["tools"][0]["auth"]["value"] = "PRIVATE_LITERAL_SENTINEL ${MIGRATION_X}".into();
    for config in [
        yaml("x-api-key", "MIGRATION_X", Some("Bearer ")),
        yaml("x-api-key", "MIGRATION_X", Some("PRIVATE_PREFIX_SENTINEL")),
        string,
    ] {
        let f = Fixture::new().await;
        header_registration(&f).await;
        let path = write(&f, &config);
        let mut p = preview(&f, &path);
        assert_eq!(row(&p, f.ids[0], "api")["action"], "skip");
        assert!(
            row(&p, f.ids[0], "api")["reason"]
                .as_str()
                .unwrap()
                .contains("owner_mapping")
        );
        assert_eq!(row(&p, f.ids[2], "api")["action"], "preserve");
        for private in ["PRIVATE_PREFIX_SENTINEL", "PRIVATE_LITERAL_SENTINEL"] {
            assert!(!p.to_string().contains(private));
        }
        p["entries"][0]["selected"] = true.into();
        p["entries"][0]["action"] = "propose".into();
        conflict(&apply(&f, &p, &path));
        assert_eq!(f.count().await, 1);
    }
}
#[tokio::test]
async fn differing_or_duplicate_supplied_source_cannot_become_a_template_guess() {
    let f = Fixture::new().await;
    header_registration(&f).await;
    let path = write(&f, &yaml("x-api-key", "MIGRATION_Y", None));
    let p = preview(&f, &path);
    assert_eq!(
        row(&p, f.ids[0], "api")["reason"],
        "legacy_source_reference_mismatch_owner_mapping_required"
    );
    let mut duplicate = yaml("x-api-key", "MIGRATION_X", None);
    let entry = duplicate["tools"][0].clone();
    duplicate["tools"].as_array_mut().unwrap().push(entry);
    let path = write(&f, &duplicate);
    assert_eq!(
        row(&preview(&f, &path), f.ids[0], "api")["reason"],
        "ambiguous_legacy_source_owner_mapping_required"
    );
}

#[tokio::test]
async fn supplied_legacy_string_reference_drift_is_pinned_without_literal_values() {
    let f = Fixture::new().await;
    let mut config = yaml("x-api-key", "MIGRATION_X", None);
    config["tools"][0]["name"] = "unmapped-legacy".into();
    config["tools"][0]["auth"]["value"] = "PRIVATE_LITERAL_SENTINEL ${BEFORE}".into();
    let path = write(&f, &config);
    let mut p = preview(&f, &path);
    assert_eq!(p["legacy"][0]["reference"]["env_var"], "BEFORE");
    assert!(!p.to_string().contains("PRIVATE_LITERAL_SENTINEL"));
    select(&mut p, f.ids[0]);
    config["tools"][0]["auth"]["value"] = "PRIVATE_LITERAL_SENTINEL ${AFTER}".into();
    write(&f, &config);
    conflict(&apply(&f, &p, &path));
    assert_eq!(f.count().await, 1);
}
