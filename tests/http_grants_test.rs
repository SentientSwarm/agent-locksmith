//! D4 authority at the persisted repository and reviewed cutover boundaries.
use agent_locksmith::{
    auth_v2::{AgentAuthenticator, BearerAuthenticator},
    binding_migration,
    migrations::open_and_migrate,
    registrations::{AuthSpec, Kind, Registration, RegistrationRepository},
    repo::{AgentCredentialRepository, AgentRepository},
};
use secrecy::ExposeSecret;

async fn connection(repo: &RegistrationRepository, name: &str) {
    repo.create(&Registration::new(
        name.into(),
        Kind::Tool,
        String::new(),
        "http://127.0.0.1:1".into(),
        AuthSpec::None,
    ))
    .await
    .unwrap();
}

#[tokio::test]
async fn delete_recreate_and_destination_replacement_remove_authority_atomically() {
    let tmp = tempfile::tempdir().unwrap();
    let pool = open_and_migrate(&tmp.path().join("db")).await.unwrap();
    let regs = RegistrationRepository::new(pool.clone());
    let agents = AgentRepository::new(pool.clone());
    let bindings = AgentCredentialRepository::new(pool.clone());
    connection(&regs, "service").await;
    let (pid, _) = agents
        .create("caller", None, Some(&["service".into()]), None, None, None)
        .await
        .unwrap();
    let id = agents
        .get_active_by_public_id(&pid)
        .await
        .unwrap()
        .unwrap()
        .id;
    bindings.set(id, "service", &AuthSpec::None).await.unwrap();
    assert!(bindings.set(id, "future", &AuthSpec::None).await.is_err());
    regs.delete("service").await.unwrap();
    assert!(bindings.get(id, "service").await.unwrap().is_none());
    assert_eq!(
        agents
            .get_active_by_public_id(&pid)
            .await
            .unwrap()
            .unwrap()
            .tool_allowlist,
        Some(vec![])
    );
    connection(&regs, "service").await;
    assert!(bindings.get(id, "service").await.unwrap().is_none());
    agents
        .update_policy(&pid, Some(Some(vec!["service".into()])), None, None, None)
        .await
        .unwrap();
    bindings.set(id, "service", &AuthSpec::None).await.unwrap();
    regs.set_disabled("service", true).await.unwrap();
    assert!(bindings.get(id, "service").await.unwrap().is_some());
    regs.set_disabled("service", false).await.unwrap();
    let mut changed = regs.get("service").await.unwrap().unwrap();
    changed.upstream = "http://127.0.0.1:2".into();
    regs.upsert(&changed).await.unwrap();
    assert!(bindings.get(id, "service").await.unwrap().is_none());
    assert_eq!(
        agents
            .get_active_by_public_id(&pid)
            .await
            .unwrap()
            .unwrap()
            .tool_allowlist,
        Some(vec![])
    );
    pool.close().await;
}

#[tokio::test]
async fn reviewed_finite_migration_preserves_references_and_blocks_future_and_replay() {
    let tmp = tempfile::tempdir().unwrap();
    let db = tmp.path().join("db");
    let pool = open_and_migrate(&db).await.unwrap();
    let regs = RegistrationRepository::new(pool.clone());
    let agents = AgentRepository::new(pool.clone());
    let bindings = AgentCredentialRepository::new(pool.clone());
    connection(&regs, "current").await;
    let mut callers = Vec::new();
    for (name, allow) in [
        ("restricted", Some(vec!["current".into(), "future".into()])),
        ("legacy-all", None),
        ("empty", Some(vec![])),
    ] {
        let (pid, secret) = agents
            .create(name, None, allow.as_deref(), None, None, None)
            .await
            .unwrap();
        let agent = agents.get_active_by_public_id(&pid).await.unwrap().unwrap();
        // Model the exact pre-D4 row; production creates reviewed finite policy.
        sqlx::query("UPDATE agents SET grants_reviewed=0, tool_allowlist=? WHERE id=?")
            .bind(allow.map(|a| serde_json::to_string(&a).unwrap()))
            .bind(agent.id)
            .execute(&pool)
            .await
            .unwrap();
        bindings
            .set(agent.id, "current", &AuthSpec::None)
            .await
            .unwrap();
        callers.push((
            pid.clone(),
            agent.id,
            format!("Bearer lk_{pid}.{}", secret.expose_secret()),
        ));
    }
    let auth = BearerAuthenticator::new(agents.clone()).unwrap();
    for (_, _, token) in &callers {
        assert!(
            auth.authenticate_bearer(token)
                .await
                .unwrap()
                .allows_tool("current")
                .is_err()
        );
    }
    let mut p = binding_migration::preview_grants(&db, None).await.unwrap();
    assert_eq!(p.format_version, 2);
    assert_eq!(p.grants[0].allowlist, ["current"]);
    assert_eq!(p.grants[1].allowlist, ["current"]);
    assert!(p.grants[2].allowlist.is_empty());
    assert!(p.entries.iter().all(|e| e.action == "preserve"));
    for g in &mut p.grants {
        g.selected = true;
    }
    assert_eq!(binding_migration::apply(&db, &p, None).await.unwrap(), 0);
    assert_eq!(binding_migration::apply(&db, &p, None).await.unwrap(), 0);
    connection(&regs, "future").await;
    for (_, id, token) in &callers {
        assert_eq!(
            bindings
                .get(*id, "current")
                .await
                .unwrap()
                .unwrap()
                .auth_spec,
            AuthSpec::None
        );
        bindings.set(*id, "future", &AuthSpec::None).await.unwrap();
        let identity = auth.authenticate_bearer(token).await.unwrap();
        assert!(identity.allows_tool("future").is_err());
        assert_eq!(identity.allows_tool("current").is_ok(), *id != callers[2].1);
    }
    agents.revoke(&callers[0].0).await.unwrap();
    assert!(binding_migration::apply(&db, &p, None).await.is_err());
    assert!(auth.authenticate_bearer(&callers[0].2).await.is_err());
    pool.close().await;
}

#[test]
fn authority_payloads_reject_unsupported_selectors() {
    use agent_locksmith::admin::service::{
        CreateAgentInput, MintBootstrapInput, ModifyAgentInput, RegisterInput,
    };
    assert!(
        serde_json::from_value::<CreateAgentInput>(
            serde_json::json!({"name":"a", "methods":["GET"]})
        )
        .is_err()
    );
    assert!(
        serde_json::from_value::<ModifyAgentInput>(serde_json::json!({"resources":["/safe"]}))
            .is_err()
    );
    assert!(
        serde_json::from_value::<MintBootstrapInput>(serde_json::json!({"operations":["read"]}))
            .is_err()
    );
    assert!(
        serde_json::from_value::<RegisterInput>(
            serde_json::json!({"bootstrap_token":"unused", "name":"a", "allowlist":["future"]})
        )
        .is_err()
    );
    let clear: ModifyAgentInput =
        serde_json::from_value(serde_json::json!({"allowlist":null})).unwrap();
    assert_eq!(clear.allowlist, Some(None));
    assert!(clear.denylist.is_none());
}

#[tokio::test]
async fn bootstrap_issuance_is_finite_and_old_templates_require_reminting() {
    use agent_locksmith::repo::bootstrap::{BootstrapScope, BootstrapTokenRepository};
    let tmp = tempfile::tempdir().unwrap();
    let pool = open_and_migrate(&tmp.path().join("db")).await.unwrap();
    let regs = RegistrationRepository::new(pool.clone());
    let tokens = BootstrapTokenRepository::new(pool.clone());
    connection(&regs, "service").await;
    let (empty, _) = tokens
        .mint(
            BootstrapScope {
                tool_allowlist: None,
                expires_at: None,
                single_use: true,
            },
            "operator",
        )
        .await
        .unwrap();
    assert_eq!(
        tokens.preview_scope(&empty).await.unwrap().tool_allowlist,
        Some(vec![])
    );
    let (scoped, _) = tokens
        .mint(
            BootstrapScope {
                tool_allowlist: Some(vec!["service".into()]),
                expires_at: None,
                single_use: true,
            },
            "operator",
        )
        .await
        .unwrap();
    regs.delete("service").await.unwrap();
    connection(&regs, "service").await;
    assert_eq!(
        tokens.preview_scope(&scoped).await.unwrap().tool_allowlist,
        Some(vec![])
    );
    sqlx::query("UPDATE bootstrap_tokens SET grants_reviewed=0 WHERE public_id=?")
        .bind(&scoped)
        .execute(&pool)
        .await
        .unwrap();
    assert!(tokens.preview_scope(&scoped).await.is_err());
}

#[tokio::test]
async fn enrollment_cannot_restore_scope_removed_after_preview() {
    use agent_locksmith::{
        admin::{AdminService, service::RegisterInput},
        config::parse_config_str,
        repo::bootstrap::{BootstrapScope, BootstrapTokenRepository},
    };
    for lifecycle in [
        "UPDATE registrations SET upstream='http://127.0.0.1:2' WHERE name='service';",
        "DELETE FROM registrations WHERE name='service'; INSERT INTO registrations(name,kind,upstream,auth_json,timeouts_json,created_at,updated_at) VALUES ('service','tool','http://127.0.0.1:2','{\"kind\":\"none\"}','{}',1,1);",
    ] {
        for single_use in [true, false] {
            let tmp = tempfile::tempdir().unwrap();
            let pool = open_and_migrate(&tmp.path().join("db")).await.unwrap();
            let regs = RegistrationRepository::new(pool.clone());
            connection(&regs, "service").await;
            let agents = AgentRepository::new(pool.clone());
            let tokens = BootstrapTokenRepository::new(pool.clone());
            let (pid, secret) = tokens
                .mint(
                    BootstrapScope {
                        tool_allowlist: Some(vec!["service".into()]),
                        expires_at: None,
                        single_use,
                    },
                    "operator",
                )
                .await
                .unwrap();
            // Deterministically interleave scope cleanup after enrollment's preview.
            sqlx::query(&format!(
                "CREATE TRIGGER scope_cutover BEFORE INSERT ON agents BEGIN {lifecycle} END"
            ))
            .execute(&pool)
            .await
            .unwrap();
            let service = AdminService::new(
                agents.clone(),
                tokens,
                std::sync::Arc::new(arc_swap::ArcSwap::from_pointee(
                    parse_config_str("listen:\n  port: 9200\n").unwrap(),
                )),
            );
            let result = service
                .register_agent(RegisterInput {
                    bootstrap_token: format!("lkbt_{pid}.{}", secret.expose_secret()).into(),
                    name: "caller".into(),
                    description: None,
                    metadata: None,
                })
                .await;
            assert!(
                result.is_err(),
                "changed enrollment scope must not issue stale authority"
            );
            assert!(
                agents
                    .get_by_name("caller")
                    .await
                    .unwrap()
                    .unwrap()
                    .revoked_at
                    .is_some()
            );
        }
    }
}

#[tokio::test]
async fn grant_writes_validate_current_targets_in_the_committing_statement() {
    use agent_locksmith::repo::bootstrap::{BootstrapScope, BootstrapTokenRepository};
    let tmp = tempfile::tempdir().unwrap();
    let pool = open_and_migrate(&tmp.path().join("db")).await.unwrap();
    let regs = RegistrationRepository::new(pool.clone());
    let agents = AgentRepository::new(pool.clone());
    let tokens = BootstrapTokenRepository::new(pool.clone());
    let names = vec!["service".into()];
    connection(&regs, "service").await;
    let (existing, _) = agents
        .create_reviewed("existing", None, Some(&names), None, None, None)
        .await
        .unwrap();
    // A writer removes the target after a caller's earlier successful validation.
    agents.validate_grants(&names).await.unwrap();
    regs.delete("service").await.unwrap();
    assert!(
        agents
            .create_reviewed("new", None, Some(&names), None, None, None)
            .await
            .is_err()
    );
    assert!(agents.get_by_name("new").await.unwrap().is_none());
    assert!(
        agents
            .update_policy_reviewed(&existing, Some(Some(names.clone())), None, None, None)
            .await
            .is_err()
    );
    assert!(
        tokens
            .mint_reviewed(
                BootstrapScope {
                    tool_allowlist: Some(names.clone()),
                    expires_at: None,
                    single_use: false
                },
                "operator"
            )
            .await
            .is_err()
    );
    assert!(tokens.list().await.unwrap().is_empty());
    assert_eq!(
        agents
            .get_by_name("existing")
            .await
            .unwrap()
            .unwrap()
            .tool_allowlist,
        Some(vec![])
    );
    // Deliberate reapproval after recreation is valid, then destination cleanup still wins.
    connection(&regs, "service").await;
    agents
        .update_policy_reviewed(&existing, Some(Some(names)), None, None, None)
        .await
        .unwrap();
    let mut changed = regs.get("service").await.unwrap().unwrap();
    changed.upstream = "http://127.0.0.1:2".into();
    regs.upsert(&changed).await.unwrap();
    assert_eq!(
        agents
            .get_by_name("existing")
            .await
            .unwrap()
            .unwrap()
            .tool_allowlist,
        Some(vec![])
    );
}
