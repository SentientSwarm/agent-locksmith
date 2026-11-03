//! Manual owner snapshot import using existing sources and authenticated APIs.
use agent_locksmith::admin::uds_client::UdsClient;
use agent_locksmith::secret::{FileSealedBackend, SecretRef, SecretResolver};
use base64::Engine;
use secrecy::ExposeSecret;
use serde_json::{Value, json};
use std::path::Path;

pub fn enable_stored_source() {
    let key = base64::engine::general_purpose::STANDARD.encode([0xd1; 32]);
    // Synthetic key in this integration-test process, never the owner's daemon.
    unsafe { std::env::set_var("LOCKSMITH_CREDENTIAL_SEALING_KEY", key) };
}

async fn admin(
    client: &UdsClient,
    op: &str,
    method: &str,
    path: &str,
    body: Option<Value>,
) -> Value {
    let body = body.map(|v| serde_json::to_vec(&v).unwrap());
    let (status, bytes) = client
        .request(
            method,
            path,
            &[("authorization", op), ("content-type", "application/json")],
            body,
        )
        .await
        .unwrap();
    if method == "PATCH" {
        assert_eq!(status, 204);
        return Value::Null;
    }
    assert_eq!(status, 200);
    serde_json::from_slice(&bytes).unwrap()
}

pub async fn import_snapshot(socket: &Path, op: &str, file: &Path, upstream: &str) {
    let client = UdsClient::new(socket);
    // A catalog entry supplies the header shape; no env value is used/imported.
    admin(&client, op, "PUT", "/admin/operator/tools/ping", Some(json!({
        "upstream": upstream,
        "auth": {"kind": "header", "header": "authorization", "env_var": "D1_UNUSED_IMPORT_TEMPLATE"}
    }))).await;
    let resolver = SecretResolver::with_file_sealed(FileSealedBackend::new());
    let value = resolver
        .resolve(&SecretRef::FromFileSealed { path: file.into() })
        .await
        .unwrap();
    let result = admin(
        &client,
        op,
        "PUT",
        "/admin/operator/tools/ping/credential",
        Some(json!({"value": value.expose_secret()})),
    )
    .await;
    assert!(!result.to_string().contains(value.expose_secret()));
    let secret_ref = result["secret_ref"].as_str().unwrap();
    admin(&client, op, "PUT", "/admin/operator/agents/ping-agent/credentials/ping",
        Some(json!({"auth_spec": {"kind": "stored_header", "header": "authorization", "secret_ref": secret_ref}}))).await;
    let agent = admin(
        &client,
        op,
        "GET",
        "/admin/operator/agents/ping-agent",
        None,
    )
    .await;
    admin(
        &client,
        op,
        "PATCH",
        &format!(
            "/admin/operator/agents/{}",
            agent["public_id"].as_str().unwrap()
        ),
        Some(json!({"allowlist":["ping"]})),
    )
    .await;
    assert_safe_reads(&client, op, secret_ref, value.expose_secret()).await;
}

async fn assert_safe_reads(client: &UdsClient, op: &str, secret_ref: &str, secret: &str) {
    let registration = admin(client, op, "GET", "/admin/operator/tools/ping", None).await;
    assert_eq!(registration["auth"]["kind"], "stored_header");
    assert_eq!(registration["auth"]["secret_ref"], secret_ref);
    let selections = admin(
        client,
        op,
        "GET",
        "/admin/operator/agents/ping-agent/credentials",
        None,
    )
    .await;
    assert_eq!(
        selections["overrides"][0]["auth_spec"]["secret_ref"],
        secret_ref
    );
    for read in [registration, selections] {
        assert!(!read.to_string().contains(secret));
    }
}

pub async fn assert_denied(url: &str, agent: &str, mock: &wiremock::MockServer) {
    let before = mock.received_requests().await.unwrap().len();
    let response = reqwest::Client::new()
        .get(url)
        .header("authorization", agent)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 403);
    let body: Value = response.json().await.unwrap();
    assert_eq!(body["error"]["code"], "tool_not_allowed");
    assert_eq!(mock.received_requests().await.unwrap().len(), before);
}

pub async fn clear(socket: &Path, op: &str) {
    let (status, _) = UdsClient::new(socket)
        .request(
            "DELETE",
            "/admin/operator/agents/ping-agent/credentials/ping",
            &[("authorization", op)],
            None,
        )
        .await
        .unwrap();
    assert_eq!(status, 204);
}
