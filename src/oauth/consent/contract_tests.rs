//! Test-first declared contracts; all endpoints and identities are invented.
use super::*;
use serde_json::json;

#[test]
fn public_declared_profile_example_validates() {
    let profile = serde_json::from_str(include_str!(
        "../../../docs/user/operator/custom-oauth-profile.example.json"
    ))
    .unwrap();
    let cfg = config::Config {
        callback: config::Callback {
            address: "127.0.0.1:24443".parse().unwrap(),
            cert_path: "invented.pem".into(),
            key_path: "invented.key".into(),
        },
        profiles: vec![profile],
    };
    cfg.validate().expect("published declaration validates");
}

pub(super) fn declared(service: bool) -> Value {
    let subject = if service {
        json!({"kind":"service_principal","subject_id":"service-example"})
    } else {
        json!({"kind":"user_workspace","workspace_id":"tenant-example","user_id":"person-example"})
    };
    json!({"id":"unlisted","kind":"custom-oauth-v1","client_id":"invented-client",
        "client_generation":1,"issuer":"https://identity.example.test",
        "authorization_endpoint":"https://identity.example.test/authorize",
        "token_endpoint":"https://identity.example.test/token","resource":"https://api.example.test",
        "redirect_profile_id":"customer","redirect_uri":"https://callback.example.test/oauth/callback",
        "ca_path":"invented-ca.pem","contract":{"version":1,"grant":"authorization_code_s256",
        "registration":"pre_registered","client_auth":"client_secret_post",
        "approved_origins":["https://identity.example.test","https://api.example.test"],
        "mcp_endpoint":"https://api.example.test/mcp","callback":"issuer_required",
        "scope":{"required":["catalog:inspect","records:read"],"request_separator":"space","response_separator":"space"},
        "token_response":"oauth2-bearer-v1","identity":{"endpoint":"https://identity.example.test/whoami",
        "method":"get","response":if service {"service-principal-v1"} else {"workspace-user-v1"}},"subject":subject}})
}

#[test]
fn contract_profile_accepts_unlisted_user_and_service() {
    for service in [false, true] {
        let profile: config::Profile = serde_json::from_value(declared(service)).unwrap();
        let cfg = config::Config {
            callback: config::Callback {
                address: "127.0.0.1:24443".parse().unwrap(),
                cert_path: "invented.pem".into(),
                key_path: "invented.key".into(),
            },
            profiles: vec![profile],
        };
        cfg.validate().expect("supported declared custom contract");
        assert_eq!(
            cfg.profiles[0].scopes(),
            ["catalog:inspect", "records:read"]
        );
    }
}

#[test]
fn contract_root_tokens_require_exact_scope_evidence() {
    let p: config::Profile = serde_json::from_value(declared(false)).unwrap();
    let good = json!({"access_token":"invented-access", "token_type":"Bearer",
        "scope":"records:read catalog:inspect", "refresh_token":"invented-refresh", "expires_in":3600});
    let decode = |v: &Value| token::decode(&p, &serde_json::to_vec(v).unwrap());
    assert!(
        decode(&good).is_ok(),
        "no token identity echo required before independent verification"
    );
    for scope in [
        Value::Null,
        json!(false),
        json!("catalog:inspect"),
        json!("catalog:inspect records:read extra"),
        json!("catalog:inspect records:read records:read"),
    ] {
        let mut bad = good.clone();
        bad["scope"] = scope;
        assert!(decode(&bad).is_err());
    }
    absent_and_conflicting_echoes(&p, good);
}

fn absent_and_conflicting_echoes(p: &config::Profile, good: Value) {
    let decode = |v: &Value| token::decode(p, &serde_json::to_vec(v).unwrap());
    let mut absent = good.clone();
    absent.as_object_mut().unwrap().remove("scope");
    assert!(
        decode(&absent).is_err(),
        "requested scopes are never substituted"
    );
    let mut conflict = good;
    conflict["user_id"] = json!("another-person");
    assert!(
        decode(&conflict).is_err(),
        "present identity echoes remain binding"
    );
}

// Append unchanged to src/oauth/consent/contract_tests.rs for builder-owned execution.
// Reviewer-authored stored-scope assertion. Invented data only; no provider traffic.
async fn reviewer_scope_current(grammar: &str, override_scope: Option<&str>) -> bool {
    let mut p: config::Profile = serde_json::from_value(declared(false)).unwrap();
    p.contract.as_mut().unwrap().scope.response_separator = grammar.into();
    let wire_scope = if grammar == "comma" {
        "records:read,catalog:inspect"
    } else {
        "records:read catalog:inspect"
    };
    let response =
        json!({"access_token":"invented-access","token_type":"Bearer","scope":wire_scope});
    let token = token::decode(&p, &serde_json::to_vec(&response).unwrap()).unwrap();
    assert_eq!(
        token.granted_scope.as_deref(),
        Some("catalog:inspect records:read")
    );
    let c = p.contract.as_ref().unwrap();
    let db = sqlx::SqlitePool::connect("sqlite::memory:").await.unwrap();
    let row = sqlx::query("SELECT ? AS subject_json, ? AS workspace_id, ? AS user_id, ? AS client_auth, ? AS scope, 1 AS scope_echoed")
        .bind(serde_json::to_string(&c.subject).unwrap())
        .bind("tenant-example").bind("person-example").bind(&c.client_auth)
        .bind(override_scope.unwrap_or(token.granted_scope.as_deref().unwrap()))
        .fetch_one(&db).await.unwrap();
    let result = super::contract::publication::matches(&row, &p);
    db.close().await;
    result.unwrap()
}
#[tokio::test]
async fn reviewer_stored_scope_space_control() {
    assert!(reviewer_scope_current("space", None).await);
}
#[tokio::test]
async fn reviewer_stored_scope_comma_canonical_positive() {
    assert!(
        reviewer_scope_current("comma", None).await,
        "valid canonical custody must not be reparsed as comma wire evidence"
    );
}
#[tokio::test]
async fn reviewer_stored_scope_mixed_control() {
    assert!(reviewer_scope_current("space_or_comma", None).await);
}
#[tokio::test]
async fn reviewer_stored_scope_extra_remains_refused() {
    assert!(!reviewer_scope_current("space", Some("catalog:inspect records:read extra")).await);
}
