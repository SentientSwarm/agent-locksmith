//! Phase J (WEM-438, CCS-3/CCS-6) — stored-credential admin routes.
//!
//! `PUT /admin/operator/<kind>/<name>/credential` seals an operator value
//! into `credential_secrets` and rewrites the registration to a `stored_*`
//! AuthSpec carrying only the opaque `secret_ref`. `DELETE` clears it back
//! to `none`. Covers:
//!
//!   - set a stored bearer on a fresh registration → auth becomes
//!     `stored_bearer` with a `cs_` ref; the sealed value roundtrips
//!     (get + unseal == original) and is NEVER echoed in the response;
//!   - header-shaped registration → `stored_header` preserving the header;
//!   - rotation (set again) tombstones the old ref (old get → None);
//!   - delete resets auth to `none`;
//!   - when the sealing key is unset, the credential route 404s (gate).

use agent_locksmith::admin::AdminService;
use agent_locksmith::admin::uds::{UdsState, build_router};
use agent_locksmith::auth_v2::{BearerAuthenticator, OperatorAuthenticator};
use agent_locksmith::config::parse_config_str;
use agent_locksmith::migrations::open_and_migrate;
use agent_locksmith::registrations::RegistrationRepository;
use agent_locksmith::repo::{
    AgentRepository, BootstrapTokenRepository, CredentialSecretsRepository,
};
use agent_locksmith::secret::CredentialSealingKey;
use agent_locksmith::{argon2_helper, token};
use arc_swap::ArcSwap;
use axum_test::TestServer;
use serde_json::json;
use std::sync::Arc;
use tempfile::TempDir;

struct Harness {
    server: TestServer,
    op_token: String,
    /// `Some` when the credential store feature is wired — used to verify
    /// the sealed value roundtrips and that rotation tombstones the old ref.
    key: Option<CredentialSealingKey>,
    secrets: Option<CredentialSecretsRepository>,
    _dir: TempDir,
}

async fn setup(with_key: bool) -> Harness {
    let dir = TempDir::new().unwrap();

    let op_token = token::StructuredToken::generate(token::TokenNamespace::Operator);
    let op_token_wire = op_token.wire_format();
    let token_hash = argon2_helper::hash(&secrecy::SecretString::from(
        op_token.secret.expose().to_string(),
    ))
    .unwrap();
    let ops_path = dir.path().join("operators.yaml");
    std::fs::write(
        &ops_path,
        format!(
            "operators:\n  - name: alice\n    public_id: \"{}\"\n    token_hash: \"{}\"\n",
            op_token.public_id.as_str(),
            token_hash
        ),
    )
    .unwrap();

    let pool = open_and_migrate(&dir.path().join("locksmith.db"))
        .await
        .unwrap();
    let agents = AgentRepository::new(pool.clone());
    let bootstrap = BootstrapTokenRepository::new(pool.clone());
    let registrations = Arc::new(RegistrationRepository::new(pool.clone()));

    let cfg =
        parse_config_str("listen:\n  host: \"127.0.0.1\"\n  port: 9200\ntools: []\n").unwrap();
    let config = Arc::new(ArcSwap::from_pointee(cfg));

    let admin = Arc::new(AdminService::new(agents.clone(), bootstrap, config));
    let agent_auth = Arc::new(BearerAuthenticator::new(agents).unwrap());
    let operator_auth = Arc::new(OperatorAuthenticator::load(&ops_path).unwrap());

    let (key, secrets) = if with_key {
        let k = CredentialSealingKey::generate().unwrap();
        let s = CredentialSecretsRepository::new(pool.clone());
        (Some(k), Some(s))
    } else {
        (None, None)
    };

    let state = UdsState {
        admin,
        agent_auth,
        operator_auth,
        operator_mtls: None,
        registrations: Some(registrations),
        catalog: None,
        resolved_creds: None,
        oauth: None,
        agent_creds: None,
        credential_sealing_key: key.clone(),
        credential_secrets: secrets.clone(),
        operational_log: None,
    };
    let router = build_router(state);
    let server = TestServer::new(router);

    Harness {
        server,
        op_token: op_token_wire,
        key,
        secrets,
        _dir: dir,
    }
}

fn auth_header(h: &Harness) -> String {
    format!("Bearer {}", h.op_token)
}

/// Register a fresh bearer-authed tool so the credential handler has a row.
async fn put_tool(h: &Harness, name: &str, auth: serde_json::Value) {
    h.server
        .put(&format!("/admin/operator/tools/{name}"))
        .add_header("authorization", auth_header(h))
        .json(&json!({
            "upstream": "https://api.example.com",
            "auth": auth,
        }))
        .await
        .assert_status_ok();
}

async fn get_tool(h: &Harness, name: &str) -> serde_json::Value {
    h.server
        .get(&format!("/admin/operator/tools/{name}"))
        .add_header("authorization", auth_header(h))
        .await
        .json()
}

// ─── set a stored bearer → stored_bearer + roundtrip + no value echo ────────
#[tokio::test]
async fn set_credential_makes_stored_bearer_and_roundtrips() {
    let h = setup(true).await;
    put_tool(
        &h,
        "tavily",
        json!({ "kind": "bearer", "env_var": "TAVILY_KEY" }),
    )
    .await;

    let resp = h
        .server
        .put("/admin/operator/tools/tavily/credential")
        .add_header("authorization", auth_header(&h))
        .json(&json!({ "value": "sk-secret-abc-123" }))
        .await;
    resp.assert_status_ok();
    let body: serde_json::Value = resp.json();
    let secret_ref = body["secret_ref"].as_str().unwrap();
    assert!(secret_ref.starts_with("cs_"), "ref: {secret_ref}");
    assert!(body["set_at"].as_i64().unwrap() > 0);
    // Reveal-never: the response must not contain the cleartext value.
    assert!(
        !resp.text().contains("sk-secret-abc-123"),
        "response echoed the credential value"
    );

    // Registration auth is now stored_bearer with that ref, no value field.
    let reg = get_tool(&h, "tavily").await;
    assert_eq!(reg["auth"]["kind"], "stored_bearer");
    assert_eq!(reg["auth"]["secret_ref"], secret_ref);
    assert!(reg["auth"].get("value").is_none());

    // The sealed value roundtrips: get + unseal == original.
    let sealed = h.secrets.unwrap().get(secret_ref).await.unwrap().unwrap();
    let plain = h
        .key
        .unwrap()
        .unseal(&sealed.sealed_value, &sealed.nonce)
        .unwrap();
    assert_eq!(plain, b"sk-secret-abc-123");
}

// ─── header-shaped registration → stored_header preserves header ────────────
#[tokio::test]
async fn set_credential_preserves_header_name() {
    let h = setup(true).await;
    put_tool(
        &h,
        "anthropic",
        json!({ "kind": "header", "header": "x-api-key", "env_var": "ANTH_KEY" }),
    )
    .await;

    h.server
        .put("/admin/operator/tools/anthropic/credential")
        .add_header("authorization", auth_header(&h))
        .json(&json!({ "value": "anthropic-secret" }))
        .await
        .assert_status_ok();

    let reg = get_tool(&h, "anthropic").await;
    assert_eq!(reg["auth"]["kind"], "stored_header");
    assert_eq!(reg["auth"]["header"], "x-api-key");
    assert!(
        reg["auth"]["secret_ref"]
            .as_str()
            .unwrap()
            .starts_with("cs_")
    );
}

// ─── rotation tombstones the old ref ────────────────────────────────────────
#[tokio::test]
async fn rotating_tombstones_the_old_ref() {
    let h = setup(true).await;
    put_tool(
        &h,
        "tavily",
        json!({ "kind": "bearer", "env_var": "TAVILY_KEY" }),
    )
    .await;

    let first: serde_json::Value = h
        .server
        .put("/admin/operator/tools/tavily/credential")
        .add_header("authorization", auth_header(&h))
        .json(&json!({ "value": "first-value" }))
        .await
        .json();
    let first_ref = first["secret_ref"].as_str().unwrap().to_string();

    let second: serde_json::Value = h
        .server
        .put("/admin/operator/tools/tavily/credential")
        .add_header("authorization", auth_header(&h))
        .json(&json!({ "value": "second-value" }))
        .await
        .json();
    let second_ref = second["secret_ref"].as_str().unwrap().to_string();
    assert_ne!(first_ref, second_ref);

    let secrets = h.secrets.unwrap();
    // Old ref is tombstoned → invisible to get.
    assert!(secrets.get(&first_ref).await.unwrap().is_none());
    // New ref is live and unseals to the new value.
    let live = secrets.get(&second_ref).await.unwrap().unwrap();
    let plain = h
        .key
        .unwrap()
        .unseal(&live.sealed_value, &live.nonce)
        .unwrap();
    assert_eq!(plain, b"second-value");
}

// ─── delete resets auth to none + tombstones the ref ────────────────────────
#[tokio::test]
async fn delete_credential_resets_to_none() {
    let h = setup(true).await;
    put_tool(
        &h,
        "tavily",
        json!({ "kind": "bearer", "env_var": "TAVILY_KEY" }),
    )
    .await;

    let set: serde_json::Value = h
        .server
        .put("/admin/operator/tools/tavily/credential")
        .add_header("authorization", auth_header(&h))
        .json(&json!({ "value": "to-be-cleared" }))
        .await
        .json();
    let secret_ref = set["secret_ref"].as_str().unwrap().to_string();

    h.server
        .delete("/admin/operator/tools/tavily/credential")
        .add_header("authorization", auth_header(&h))
        .await
        .assert_status_ok();

    let reg = get_tool(&h, "tavily").await;
    assert_eq!(reg["auth"]["kind"], "none");
    // The sealed row is tombstoned.
    assert!(h.secrets.unwrap().get(&secret_ref).await.unwrap().is_none());
}

// ─── delete is idempotent when nothing is stored ────────────────────────────
#[tokio::test]
async fn delete_credential_is_idempotent() {
    let h = setup(true).await;
    put_tool(
        &h,
        "tavily",
        json!({ "kind": "bearer", "env_var": "TAVILY_KEY" }),
    )
    .await;
    // Never set a stored value; delete still 200s and leaves auth intact.
    h.server
        .delete("/admin/operator/tools/tavily/credential")
        .add_header("authorization", auth_header(&h))
        .await
        .assert_status_ok();
    let reg = get_tool(&h, "tavily").await;
    assert_eq!(reg["auth"]["kind"], "bearer");
}

// ─── the sealing-key gate: unset key → credential route 404s ────────────────
#[tokio::test]
async fn credential_route_404s_when_key_unset() {
    let h = setup(false).await;
    put_tool(
        &h,
        "tavily",
        json!({ "kind": "bearer", "env_var": "TAVILY_KEY" }),
    )
    .await;

    let resp = h
        .server
        .put("/admin/operator/tools/tavily/credential")
        .add_header("authorization", auth_header(&h))
        .json(&json!({ "value": "wont-store" }))
        .await;
    resp.assert_status(axum::http::StatusCode::NOT_FOUND);

    let del = h
        .server
        .delete("/admin/operator/tools/tavily/credential")
        .add_header("authorization", auth_header(&h))
        .await;
    del.assert_status(axum::http::StatusCode::NOT_FOUND);
}

// ─── unknown registration → 404 ─────────────────────────────────────────────
#[tokio::test]
async fn set_credential_on_unknown_name_404s() {
    let h = setup(true).await;
    let resp = h
        .server
        .put("/admin/operator/tools/nope/credential")
        .add_header("authorization", auth_header(&h))
        .json(&json!({ "value": "x" }))
        .await;
    resp.assert_status(axum::http::StatusCode::NOT_FOUND);
}
