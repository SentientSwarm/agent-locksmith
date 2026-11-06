use super::fixture::{Fixture, definition, instance};
use serde_json::{Value, json};

async fn get(f: &Fixture) -> Value {
    f.server
        .get("/admin/operator/tools/customer")
        .add_header("authorization", &f.token)
        .await
        .json()
}

#[tokio::test]
async fn deliberate_activation_preserves_pin_and_has_no_implicit_authority() {
    let f = Fixture::new().await;
    f.import(&definition())
        .await
        .assert_status(axum::http::StatusCode::CREATED);
    f.create("customer", &instance())
        .await
        .assert_status(axum::http::StatusCode::CREATED);
    let initial = get(&f).await;
    assert_eq!(initial["definition_control"]["phase"], "disabled");
    let revision = initial["definition_control"]["revision"].as_str().unwrap();
    let url = "/admin/operator/tools/customer/definition-activation";
    let response = f
        .server
        .put(url)
        .add_header("authorization", &f.token)
        .add_header("if-match", revision)
        .json(&json!({"enabled":true,"compact":true}))
        .await;
    response.assert_status_ok();
    let active: Value = response.json();
    assert_eq!(active["disabled"], false);
    assert_eq!(active["authoring_only"], false);
    assert_eq!(active["definition_control"]["selection_kind"], "none");
    assert_eq!(active["mcp"]["definition"], initial["mcp"]["definition"]);
    assert_eq!(active["mcp"]["compact"], true);
    assert_eq!(active["activation"], "pending"); // No runtime catalog in this fixture.
    for table in [
        "agent_credential_overrides",
        "credential_secrets",
        "oauth_sessions",
        "agents",
        "bootstrap_tokens",
    ] {
        assert_eq!(super::storage::count(&f, table).await, 0, "{table}");
    }
    f.server
        .put(url)
        .add_header("authorization", &f.token)
        .add_header("if-match", revision)
        .json(&json!({"enabled":true,"compact":true}))
        .await
        .assert_status_conflict();
    let revision = active["definition_control"]["revision"].as_str().unwrap();
    let row = f.repo.get("customer").await.unwrap().unwrap();
    f.server
        .put(url)
        .add_header("authorization", &f.token)
        .add_header("if-match", revision)
        .json(&json!({"enabled":true,"compact":true}))
        .await
        .assert_status_ok();
    assert_eq!(get(&f).await, active);
    assert_eq!(f.repo.get("customer").await.unwrap().unwrap(), row);
    f.server
        .put(url)
        .add_header("authorization", &f.token)
        .add_header("if-match", revision)
        .json(&json!({"enabled":false}))
        .await
        .assert_status_ok();
    let disabled = get(&f).await;
    assert_eq!(disabled["disabled"], true);
    assert_eq!(disabled["mcp"]["definition"], initial["mcp"]["definition"]);
    assert_eq!(disabled["mcp"]["compact"], true);
    assert!(disabled["mcp"].get("definition_activation").is_none());
    assert_ne!(
        disabled["definition_control"]["revision"],
        active["definition_control"]["revision"]
    );
}

#[tokio::test]
async fn activation_strict_input_stale_aba_and_generic_writers_are_atomic() {
    let f = Fixture::new().await;
    f.import(&definition())
        .await
        .assert_status(axum::http::StatusCode::CREATED);
    f.create("customer", &instance())
        .await
        .assert_status(axum::http::StatusCode::CREATED);
    let initial = get(&f).await;
    let rev = initial["definition_control"]["revision"].as_str().unwrap();
    let url = "/admin/operator/tools/customer/definition-activation";
    f.server
        .put(url)
        .add_header("authorization", &f.token)
        .json(&json!({"enabled":true,"compact":false}))
        .await
        .assert_status(axum::http::StatusCode::PRECONDITION_REQUIRED);
    for body in [
        json!({"enabled":true}),
        json!({"enabled":null,"compact":false}),
        json!({"enabled":true,"compact":null}),
        json!({"enabled":false,"compact":false}),
        json!({"enabled":true,"compact":false,"oauth_profile_id":null}),
        json!({"enabled":true,"compact":false,"oauth_profile_id":"other"}),
        json!({"enabled":true,"compact":false,"extra":1}),
    ] {
        f.server
            .put(url)
            .add_header("authorization", &f.token)
            .add_header("if-match", rev)
            .json(&body)
            .await
            .assert_status_bad_request();
        assert_eq!(get(&f).await, initial);
    }
    for bytes in [
        r#"{"enabled":true,"enabled":false,"compact":false}"#.to_owned(),
        " ".repeat(65537),
    ] {
        f.server
            .put(url)
            .add_header("authorization", &f.token)
            .add_header("if-match", rev)
            .content_type("application/json")
            .bytes(bytes.into())
            .await
            .assert_status_bad_request();
    }
    f.server
        .put(url)
        .add_header("authorization", &f.token)
        .add_header("if-match", rev)
        .json(&json!({"enabled":true,"compact":false}))
        .await
        .assert_status_ok();
    let active = get(&f).await;
    let row = f.repo.get("customer").await.unwrap().unwrap();
    assert!(f.repo.upsert(&row).await.is_err());
    assert!(f.repo.set_disabled("customer", true).await.is_err());
    let mut manual = row.clone();
    manual.name = "forged".into();
    manual.mcp.as_mut().unwrap().definition = None;
    assert!(f.repo.create(&manual).await.is_err());
    f.server
        .put(url)
        .add_header("authorization", &f.token)
        .add_header(
            "if-match",
            active["definition_control"]["revision"].as_str().unwrap(),
        )
        .json(&json!({"enabled":true,"compact":true}))
        .await
        .assert_status_conflict();
    f.repo.delete("customer").await.unwrap();
    f.create("customer", &instance())
        .await
        .assert_status(axum::http::StatusCode::CREATED);
    f.server
        .put(url)
        .add_header("authorization", &f.token)
        .add_header("if-match", rev)
        .json(&json!({"enabled":true,"compact":false}))
        .await
        .assert_status_conflict();
    assert_eq!(get(&f).await["disabled"], true);
}

#[tokio::test]
async fn promoted_none_requires_explicit_selection_and_deactivation_retires_it() {
    use agent_locksmith::registrations::AuthSpec;
    use agent_locksmith::repo::{AgentCredentialRepository, AgentRepository};
    let f = Fixture::new().await;
    f.import(&definition())
        .await
        .assert_status(axum::http::StatusCode::CREATED);
    f.create("customer", &instance())
        .await
        .assert_status(axum::http::StatusCode::CREATED);
    let agents = AgentRepository::new(f.pool.clone());
    agents
        .create("caller", None, None, None, None, None)
        .await
        .unwrap();
    let a = agents.get_by_name("caller").await.unwrap().unwrap();
    let bindings = AgentCredentialRepository::new(f.pool.clone());
    assert!(
        bindings
            .set(a.id, "customer", &AuthSpec::None)
            .await
            .is_err()
    );
    let before = get(&f).await;
    let url = "/admin/operator/tools/customer/definition-activation";
    f.server
        .put(url)
        .add_header("authorization", &f.token)
        .add_header(
            "if-match",
            before["definition_control"]["revision"].as_str().unwrap(),
        )
        .json(&json!({"enabled":true,"compact":false}))
        .await
        .assert_status_ok();
    assert!(bindings.get(a.id, "customer").await.unwrap().is_none());
    agents
        .update_policy(
            &a.public_id,
            Some(Some(vec!["customer".into()])),
            None,
            None,
            None,
        )
        .await
        .unwrap();
    bindings
        .set(a.id, "customer", &AuthSpec::None)
        .await
        .unwrap();
    for auth in [
        AuthSpec::Bearer {
            env_var: "SYNTHETIC".into(),
        },
        AuthSpec::StoredBearer {
            secret_ref: "missing".into(),
        },
    ] {
        assert!(bindings.set(a.id, "customer", &auth).await.is_err());
        assert_eq!(
            bindings
                .get(a.id, "customer")
                .await
                .unwrap()
                .unwrap()
                .auth_spec,
            AuthSpec::None
        );
    }
    let active = get(&f).await;
    let revision = active["definition_control"]["revision"].as_str().unwrap();
    f.server
        .put(url)
        .add_header("authorization", &f.token)
        .add_header("if-match", revision)
        .json(&json!({"enabled":true,"compact":false}))
        .await
        .assert_status_ok();
    assert!(bindings.get(a.id, "customer").await.unwrap().is_some());
    f.server
        .put(url)
        .add_header("authorization", &f.token)
        .add_header("if-match", revision)
        .json(&json!({"enabled":false}))
        .await
        .assert_status_ok();
    assert!(bindings.get(a.id, "customer").await.unwrap().is_none());
    let allowed: String = sqlx::query_scalar("SELECT tool_allowlist FROM agents WHERE id=?")
        .bind(a.id)
        .fetch_one(&f.pool)
        .await
        .unwrap();
    assert!(!allowed.contains("customer"));
}

#[tokio::test]
async fn unsupported_declarations_never_promote_or_create_authority() {
    for (mechanism, scopes, profile) in [
        ("header", json!([]), None),
        ("none", json!(["read"]), None),
        ("bearer", json!(["read"]), None),
        ("oauth_provider", json!([]), Some("unavailable")),
        ("oauth_provider", json!(["read"]), Some("unavailable")),
    ] {
        let f = Fixture::new().await;
        let mut d = definition();
        d["auth_profiles"][0]["mechanism"] = json!(mechanism);
        d["auth_profiles"][0]["required_scopes"] = scopes;
        f.import(&d)
            .await
            .assert_status(axum::http::StatusCode::CREATED);
        f.create("customer", &instance())
            .await
            .assert_status(axum::http::StatusCode::CREATED);
        let before = get(&f).await;
        let mut body = json!({"enabled":true,"compact":false});
        if let Some(p) = profile {
            body["oauth_profile_id"] = json!(p);
        }
        f.server
            .put("/admin/operator/tools/customer/definition-activation")
            .add_header("authorization", &f.token)
            .add_header(
                "if-match",
                before["definition_control"]["revision"].as_str().unwrap(),
            )
            .json(&body)
            .await
            .assert_status(if mechanism == "oauth_provider" {
                axum::http::StatusCode::SERVICE_UNAVAILABLE
            } else {
                axum::http::StatusCode::BAD_REQUEST
            });
        assert_eq!(get(&f).await, before);
        assert_eq!(super::storage::count(&f, "oauth_sessions").await, 0);
    }
    let f = Fixture::new().await;
    let d: Value = serde_json::from_str(include_str!("../../definitions/linear.json")).unwrap();
    f.import(&d)
        .await
        .assert_status(axum::http::StatusCode::CREATED);
    let mut i = instance();
    i["definition"] = json!({"id":d["id"],"revision":d["revision"]});
    i["auth_profile_id"] = d["auth_profiles"][0]["id"].clone();
    f.create("customer", &i)
        .await
        .assert_status(axum::http::StatusCode::CREATED);
    let before = get(&f).await;
    f.server
        .put("/admin/operator/tools/customer/definition-activation")
        .add_header("authorization", &f.token)
        .add_header(
            "if-match",
            before["definition_control"]["revision"].as_str().unwrap(),
        )
        .json(&json!({"enabled":true,"compact":false,"oauth_profile_id":"unavailable"}))
        .await
        .assert_status_bad_request();
    assert_eq!(get(&f).await, before);
}
#[tokio::test]
async fn competing_activation_has_one_transition_and_wrong_ingestion_rolls_back() {
    use agent_locksmith::repo::AgentRepository;
    let f = Fixture::new().await;
    f.import(&definition())
        .await
        .assert_status(axum::http::StatusCode::CREATED);
    f.create("customer", &instance())
        .await
        .assert_status(axum::http::StatusCode::CREATED);
    let before = get(&f).await;
    let rev = before["definition_control"]["revision"].as_str().unwrap();
    let url = "/admin/operator/tools/customer/definition-activation";
    let request = || {
        f.server
            .put(url)
            .add_header("authorization", &f.token)
            .add_header("if-match", rev)
            .json(&json!({"enabled":true,"compact":false}))
    };
    let (a, b) = tokio::join!(request(), request());
    let mut codes = [a.status_code().as_u16(), b.status_code().as_u16()];
    codes.sort();
    assert_eq!(codes, [200, 409]);
    let agents = AgentRepository::new(f.pool.clone());
    agents
        .create("caller", None, None, None, None, None)
        .await
        .unwrap();
    let a = agents.get_by_name("caller").await.unwrap().unwrap();
    let count = super::storage::count(&f, "credential_secrets").await;
    let response = f
        .server
        .put(&format!(
            "/admin/operator/agents/{}/credentials/customer/credential",
            a.public_id
        ))
        .add_header("authorization", &f.token)
        .json(&json!({"value":"synthetic-secret","bearer":true}))
        .await;
    assert!(!response.status_code().is_success());
    assert_eq!(super::storage::count(&f, "credential_secrets").await, count);
    assert_eq!(
        super::storage::count(&f, "agent_credential_overrides").await,
        0
    );
}

#[tokio::test]
async fn committed_catalog_failure_is_saved_and_exact_retry_only_resyncs() {
    use agent_locksmith::registrations::{AuthSpec, Kind, Registration};
    let f = Fixture::with_catalog(true).await;
    f.import(&definition())
        .await
        .assert_status(axum::http::StatusCode::CREATED);
    f.create("customer", &instance())
        .await
        .assert_status(axum::http::StatusCode::CREATED);
    f.repo
        .create(&Registration::new(
            "other".into(),
            Kind::Tool,
            "other".into(),
            "https://example.com".into(),
            AuthSpec::None,
        ))
        .await
        .unwrap();
    sqlx::query("UPDATE registrations SET auth_json='invalid' WHERE name='other'")
        .execute(&f.pool)
        .await
        .unwrap();
    let initial = get(&f).await;
    let url = "/admin/operator/tools/customer/definition-activation";
    let response = f
        .server
        .put(url)
        .add_header("authorization", &f.token)
        .add_header(
            "if-match",
            initial["definition_control"]["revision"].as_str().unwrap(),
        )
        .json(&json!({"enabled":true,"compact":false}))
        .await;
    response.assert_status(axum::http::StatusCode::SERVICE_UNAVAILABLE);
    let v: Value = response.json();
    assert_eq!(v["saved"], true);
    assert_eq!(v["activation"], "pending");
    let saved = get(&f).await;
    assert_eq!(saved["disabled"], false);
    assert_eq!(saved["activation"], "pending");
    let row = f.repo.get("customer").await.unwrap().unwrap();
    sqlx::query("UPDATE registrations SET auth_json=? WHERE name='other'")
        .bind(json!({"kind":"none"}).to_string())
        .execute(&f.pool)
        .await
        .unwrap();
    f.server
        .put(url)
        .add_header("authorization", &f.token)
        .add_header(
            "if-match",
            saved["definition_control"]["revision"].as_str().unwrap(),
        )
        .json(&json!({"enabled":true,"compact":false}))
        .await
        .assert_status_ok();
    assert_eq!(get(&f).await["activation"], "active");
    assert_eq!(
        get(&f).await["definition_control"],
        saved["definition_control"]
    );
    assert_eq!(f.repo.get("customer").await.unwrap().unwrap(), row);
}

#[tokio::test]
async fn activation_does_not_retry_unrelated_degraded_credentials() {
    use agent_locksmith::{
        registrations::{AuthSpec, Kind, Registration},
        secret::{OpCommand, OpResolver},
    };
    use std::sync::Arc;
    struct Failed;
    impl OpCommand for Failed {
        fn read(&self, _: &str) -> Result<secrecy::SecretString, String> {
            Err("synthetic offline refusal".into())
        }
    }
    let resolver = Arc::new(OpResolver::new(Box::new(Failed), None));
    let f = Fixture::with_options(true, Some(resolver.clone())).await;
    let reference = "op://fixture/unrelated/token".to_owned();
    f.repo
        .create(&Registration::new(
            "unrelated".into(),
            Kind::Tool,
            "unrelated".into(),
            "https://example.com".into(),
            AuthSpec::OpBearer {
                reference: reference.clone(),
            },
        ))
        .await
        .unwrap();
    resolver.sync(std::slice::from_ref(&reference));
    assert_eq!(
        resolver.invocation_count(),
        1,
        "fake degraded backend control"
    );
    f.import(&definition())
        .await
        .assert_status(axum::http::StatusCode::CREATED);
    f.create("customer", &instance())
        .await
        .assert_status(axum::http::StatusCode::CREATED);
    let baseline = resolver.invocation_count();
    for enabled in [true, true, false, false] {
        let before = get(&f).await;
        let body = if enabled {
            json!({"enabled":true,"compact":true})
        } else {
            json!({"enabled":false})
        };
        f.server
            .put("/admin/operator/tools/customer/definition-activation")
            .add_header("authorization", &f.token)
            .add_header(
                "if-match",
                before["definition_control"]["revision"].as_str().unwrap(),
            )
            .json(&body)
            .await
            .assert_status_ok();
        assert_eq!(
            resolver.invocation_count(),
            baseline,
            "activation/retry must not resolve unrelated credentials"
        );
    }
    resolver.sync(std::slice::from_ref(&reference));
    assert_eq!(
        resolver.invocation_count(),
        baseline + 1,
        "degraded positive control remains retryable"
    );
}
