use super::*;
use agent_locksmith::admin::uds_client::UdsClient;

#[tokio::test]
async fn explicit_oauth_selection_snapshots_metadata_via_cli() {
    let f = start_daemon();
    let mut register = cli(&f.socket_path);
    register.env("LOCKSMITH_OP_TOKEN", &f.op_token_wire).args([
        "agent",
        "register",
        "--name",
        "oauth-fixture",
    ]);
    let output = run(register);
    let agent: Value = serde_json::from_slice(&output.stdout).unwrap();
    let id = agent["public_id"].as_str().unwrap();
    let uds = UdsClient::new(&f.socket_path);
    for catalog_kind in ["models", "tools", "infra"] {
        for kind in ["oauth_pkce", "oauth_device_code"] {
            let mut auth = serde_json::json!({"kind":kind,"client_id":"selected-client",
            "scopes":["selected-scope"],"token_url":"http://127.0.0.1:9/token"});
            if kind == "oauth_pkce" {
                auth["auth_url"] = serde_json::json!("http://127.0.0.1:9/auth");
                auth["redirect_uri"] = serde_json::json!("http://127.0.0.1:9/cb");
            } else {
                auth["device_url"] = serde_json::json!("http://127.0.0.1:9/device");
            }
            let body = serde_json::json!({"description":"fixture","upstream":"http://127.0.0.1:9", "auth":auth});
            let (status, _) = uds
                .request(
                    "PUT",
                    &format!("/admin/operator/{catalog_kind}/oauth-{catalog_kind}"),
                    &[
                        ("authorization", &format!("Bearer {}", f.op_token_wire)),
                        ("content-type", "application/json"),
                    ],
                    Some(serde_json::to_vec(&body).unwrap()),
                )
                .await
                .unwrap();
            assert_eq!(status, 200);
            let registration = format!("oauth-{catalog_kind}");
            let mut select = cli(&f.socket_path);
            select.env("LOCKSMITH_OP_TOKEN", &f.op_token_wire).args([
                "agent",
                "set-credential",
                id,
                &registration,
                "--oauth-session",
                "selected",
            ]);
            let output = run(select);
            if catalog_kind == "infra" {
                assert!(
                    !output.status.success(),
                    "infra is not an HTTP grant target"
                );
                continue;
            }
            assert!(
                output.status.success(),
                "OAuth selection for {catalog_kind}/{kind} exited {:?}",
                output.status.code()
            );
            let response: Value = serde_json::from_slice(&output.stdout).unwrap();
            auth["session_label"] = serde_json::json!("selected");
            assert_eq!(response["auth_spec"], auth);
        }
    }
}
