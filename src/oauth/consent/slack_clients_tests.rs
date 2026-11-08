use super::*;

async fn fixture() -> Fixture {
    let mut f = Fixture::new().await;
    let rt = Arc::get_mut(&mut f.rt).unwrap();
    rt.client_key = Some(crate::secret::CredentialSealingKey::generate().unwrap());
    let p = &mut rt.config.profiles[0];
    p.kind = "slack-confidential-fixture-v1".into();
    p.expected_workspace = "TTEST001".into();
    p.expected_user = "UTEST001".into();
    p.authorization_endpoint = format!("{}/oauth/v2_user/authorize", p.issuer);
    p.token_endpoint = format!("{}/api/oauth.v2.user.access", p.issuer);
    p.resource = format!("{}/mcp", p.issuer);
    let mut r = f.repo.get("fixture").await.unwrap().unwrap();
    r.auth = p.auth_spec();
    r.upstream = p.resource.clone();
    r.protocol = crate::registrations::Protocol::McpStreamableHttp;
    r.mcp = Some(
        serde_json::from_value(
            json!({"protocol_version":"2025-11-25","allow_private_destination":true}),
        )
        .unwrap(),
    );
    rt.config.validate().unwrap();
    f.repo.upsert(&r).await.unwrap();
    f
}

#[tokio::test]
async fn slack_client_live_reference_survives_sweep_and_retirement_cannot_revive() {
    let f = fixture().await;
    let p = &f.rt.config.profiles[0];
    let mut c = f.rt.pool.acquire().await.unwrap();
    assert!(clients::current(&mut c, "owner", p).await.is_err());
    drop(c);
    f.rt.set_client("owner", "fixture", "fixture", 1, "invented-client-secret")
        .await
        .unwrap();
    assert!(
        f.rt.set_client("owner", "fixture", "fixture", 1, "invented-client-secret")
            .await
            .is_err()
    );
    let repo = crate::repo::CredentialSecretsRepository::new(f.rt.pool.clone());
    let reference: String = sqlx::query_scalar("SELECT secret_ref FROM oauth_consent_clients")
        .fetch_one(&f.rt.pool)
        .await
        .unwrap();
    assert!(!repo.tombstone_if_unreferenced(&reference).await.unwrap());
    assert_eq!(repo.tombstone_unreferenced(now() + 1).await.unwrap(), 0);
    check_binding(&f).await;
    retired_gc(&f, &repo, &reference).await;
}

async fn retired_gc(f: &Fixture, repo: &crate::repo::CredentialSecretsRepository, reference: &str) {
    sqlx::query("UPDATE oauth_consent_clients SET retired_at=1")
        .execute(&f.rt.pool)
        .await
        .unwrap();
    assert!(repo.tombstone_if_unreferenced(reference).await.unwrap());
    assert_eq!(repo.sweep(now() + 1).await.unwrap(), 1);
    assert!(
        f.rt.set_client("owner", "fixture", "fixture", 1, "replacement")
            .await
            .is_err()
    );
    assert!(
        sqlx::query("DELETE FROM oauth_consent_clients")
            .execute(&f.rt.pool)
            .await
            .is_err()
    );
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM credential_secrets")
        .fetch_one(&f.rt.pool)
        .await
        .unwrap();
    assert_eq!(count, 0, "refused replacement must not insert sealed rows");
}

async fn check_binding(f: &Fixture) {
    let p = &f.rt.config.profiles[0];
    let mut c = f.rt.pool.acquire().await.unwrap();
    clients::current(&mut c, "owner", p).await.unwrap();
    assert!(clients::current(&mut c, "other", p).await.is_err());
    let mut other = p.clone();
    other.client_generation = 2;
    assert!(clients::current(&mut c, "owner", &other).await.is_err());
    use secrecy::ExposeSecret;
    assert_eq!(
        f.rt.resolve_client(&mut c, "owner", p)
            .await
            .unwrap()
            .unwrap()
            .expose_secret(),
        "invented-client-secret"
    );
}

#[tokio::test]
async fn slack_client_retirement_invalidates_pending_consent_without_network() {
    let f = fixture().await;
    f.rt.set_client("owner", "fixture", "fixture", 1, "invented-client-secret")
        .await
        .unwrap();
    let request = start_request(&f).await;
    let started = f.rt.start("owner", "fixture", &request).await.unwrap();
    sqlx::query("UPDATE oauth_consent_clients SET retired_at=1")
        .execute(&f.rt.pool)
        .await
        .unwrap();
    let poll =
        f.rt.poll("owner", "fixture", started["attempt_id"].as_str().unwrap())
            .await
            .unwrap();
    assert_eq!(poll["state"], "failed");
    assert_eq!(poll["safe_reason"], "client_retired");
    assert!(f.rt.start("owner", "fixture", &request).await.is_err());
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM oauth_sessions")
        .fetch_one(&f.rt.pool)
        .await
        .unwrap();
    assert_eq!(rows, 0);
}

async fn start_request(f: &Fixture) -> Start {
    let r = f.rt.account("owner", "fixture", "reader").await.unwrap();
    Start {
        session_label: "reader".into(),
        auth_profile_id: "fixture".into(),
        client_generation: 1,
        requested_scopes: vec!["search:read.public".into(), "channels:history".into()],
        redirect_profile_id: "loopback".into(),
        expected_config_revision: r["config_revision"].as_i64().unwrap(),
    }
}

#[tokio::test]
async fn slack_client_generation_advance_never_revives_old_context() {
    let mut f = fixture().await;
    f.rt.set_client("owner", "fixture", "fixture", 1, "invented-first")
        .await
        .unwrap();
    let old = f.rt.config.profiles[0].clone();
    advance(&mut f, 2).await;
    f.rt.set_client("owner", "fixture", "fixture", 2, "invented-second")
        .await
        .unwrap();
    let mut c = f.rt.pool.acquire().await.unwrap();
    assert!(clients::current(&mut c, "owner", &old).await.is_err());
    clients::current(&mut c, "owner", &f.rt.config.profiles[0])
        .await
        .unwrap();
    check_retired(&mut c).await;
    drop(c);
    advance(&mut f, 1).await;
    assert!(
        f.rt.set_client("owner", "fixture", "fixture", 1, "old-context")
            .await
            .is_err()
    );
    let mut c = f.rt.pool.acquire().await.unwrap();
    assert!(clients::current(&mut c, "owner", &old).await.is_err());
}

async fn advance(f: &mut Fixture, generation: u64) {
    let rt = Arc::get_mut(&mut f.rt).unwrap();
    rt.config.profiles[0].client_generation = generation;
    let mut r = f.repo.get("fixture").await.unwrap().unwrap();
    r.auth = rt.config.profiles[0].auth_spec();
    f.repo.upsert(&r).await.unwrap();
}

async fn check_retired(c: &mut sqlx::SqliteConnection) {
    let retired: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM oauth_consent_clients WHERE retired_at IS NOT NULL",
    )
    .fetch_one(c)
    .await
    .unwrap();
    assert_eq!(retired, 1);
}
