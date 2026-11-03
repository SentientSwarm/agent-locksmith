use super::{
    fixture::*,
    inventory::{add, row},
};
use agent_locksmith::registrations::AuthSpec;
use serde_json::Value;
use std::os::unix::fs::PermissionsExt;
const PRIVATE: [&str; 4] = [
    "PRIVATE_HASH_SENTINEL",
    "PRIVATE_CIPHERTEXT_SENTINEL",
    "PRIVATE_NONCE_SENTINEL",
    "PRIVATE_OP_SENTINEL",
];

async fn fixture() -> Fixture {
    let f = Fixture::new().await;
    f.exec("UPDATE agents SET secret_hash='PRIVATE_HASH_SENTINEL'")
        .await;
    add(
        &f,
        "op",
        AuthSpec::OpBearer {
            reference: "op://test/item/password".into(),
        },
    )
    .await;
    add(
        &f,
        "stored",
        AuthSpec::StoredBearer {
            secret_ref: "cs_test".into(),
        },
    )
    .await;
    f.exec("INSERT INTO credential_secrets VALUES ('cs_test',CAST('PRIVATE_CIPHERTEXT_SENTINEL' AS BLOB),CAST('PRIVATE_NONCE_SENTINEL' AS BLOB),1,NULL)").await;
    let executable = f.dir.path().join("op");
    std::fs::write(
        &executable,
        b"#!/bin/sh\nprintf called > \"$OP_MARKER\"\nprintf PRIVATE_OP_SENTINEL\n",
    )
    .unwrap();
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
    f
}
fn private_absent(text: &str) {
    for sentinel in PRIVATE {
        assert!(!text.contains(sentinel), "leaked {sentinel}");
    }
}
fn select_references(p: &mut Value, id: i64) {
    for entry in p["entries"].as_array_mut().unwrap() {
        if entry["agent_id"] == id
            && matches!(entry["registration"].as_str(), Some("op" | "stored"))
        {
            entry["selected"] = true.into();
        }
    }
}
#[tokio::test]
async fn metadata_preview_and_apply_never_read_values_hashes_or_call_op() {
    let f = fixture().await;
    let o = f.command("preview").output().unwrap();
    success(&o);
    assert!(!f.dir.path().join("called").exists());
    private_absent(&String::from_utf8_lossy(&o.stdout));
    let mut p: Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(row(&p, f.ids[0], "op")["reason"], "op_value_unverified");
    assert_eq!(
        row(&p, f.ids[0], "stored")["reason"],
        "sealed_value_unverified"
    );
    select_references(&mut p, f.ids[0]);
    let applied = f.apply(&p);
    success(&applied);
    private_absent(&String::from_utf8_lossy(&applied.stdout));
    private_absent(&String::from_utf8_lossy(&applied.stderr));
    assert!(!f.dir.path().join("called").exists());
    let receipt: String = sqlx::query_scalar(
        "SELECT value FROM registrations_meta WHERE key LIKE 'explicit_bindings/v1/plan/%'",
    )
    .fetch_one(&f.pool)
    .await
    .unwrap();
    private_absent(&receipt);
}

#[tokio::test]
async fn preview_accepts_runtime_valid_environment_names_without_reading_values() {
    for header in [false, true] {
        let f = Fixture::new().await;
        let spec = if header {
            AuthSpec::Header {
                header: "x-api-key".into(),
                env_var: "MIGRATION.KEY-X".into(),
            }
        } else {
            AuthSpec::Bearer {
                env_var: "MIGRATION.KEY-X".into(),
            }
        };
        add(&f, "non-shell-env", spec).await;
        let o = f
            .command("preview")
            .env("MIGRATION.KEY-X", "PRIVATE_NON_SHELL_ENV_SENTINEL")
            .output()
            .unwrap();
        success(&o);
        let p: Value = serde_json::from_slice(&o.stdout).unwrap();
        assert_eq!(
            row(&p, f.ids[0], "non-shell-env")["reason"],
            "env_value_unverified"
        );
        assert_eq!(row(&p, f.ids[0], "non-shell-env")["action"], "propose");
        assert!(!String::from_utf8_lossy(&o.stdout).contains("PRIVATE_NON_SHELL_ENV_SENTINEL"));
    }
}
