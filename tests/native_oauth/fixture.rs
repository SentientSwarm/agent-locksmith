//! Synthetic sealed-row setup for native authority tests; not provider acceptance.
use crate::{pki, support::Setup};
use agent_locksmith::{
    native_authority::runtime::Runtime,
    oauth::{
        SealingKey,
        consent::{
            self,
            config::{Callback, Config, Profile},
        },
    },
    registrations::AuthSpec,
};
use std::path::Path;
pub fn key() -> SealingKey {
    SealingKey::from_b64("KysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKys=").unwrap()
}
pub fn profile(path: &Path, port: u16) -> Profile {
    let issuer = format!("https://127.0.0.1:{port}");
    Profile {
        id: "controlled".into(),
        kind: "controlled-linear-v1".into(),
        selected_tools: vec![],
        client_id: "fixture-client".into(),
        client_generation: 1,
        issuer: issuer.clone(),
        authorization_endpoint: format!("{issuer}/authorize"),
        token_endpoint: format!("{issuer}/token"),
        resource: format!("{issuer}/mcp/readonly"),
        redirect_profile_id: "local".into(),
        redirect_uri: "https://127.0.0.1:19294/oauth/callback".into(),
        expected_workspace: "00000000-0000-0000-0000-000000000041".into(),
        expected_user: "00000000-0000-0000-0000-000000000042".into(),
        ca_path: path.join("ca.pem"),
    }
}
pub async fn insert(s: &Setup, p: &Profile, key: &SealingKey, label: &str, owner: &str) {
    let (ct, n) = key.seal(b"fixture-account-x").unwrap();
    sqlx::query("INSERT INTO oauth_sessions(name,session_label,kind,owner_id,profile_id,profile_digest,workspace_id,user_id,access_token_ciphertext,access_token_nonce,created_at,updated_at) VALUES('native',?,'controlled_linear_v1',?,?,?,?,?,?,?,1,1)")
      .bind(label).bind(owner).bind(&p.id).bind(p.digest().unwrap()).bind(&p.expected_workspace).bind(&p.expected_user).bind(ct).bind(n).execute(&s.f.pool).await.unwrap();
}
pub async fn configure(s: &Setup, p: &Profile) {
    let mut reg = s.f.repo.get("native").await.unwrap().unwrap();
    reg.upstream = p.resource.clone();
    reg.mcp.as_mut().unwrap().allow_private_destination = true;
    reg.auth = AuthSpec::OauthPkce {
        client_id: p.client_id.clone(),
        redirect_uri: p.redirect_uri.clone(),
        scopes: vec!["read".into()],
        auth_url: p.authorization_endpoint.clone(),
        token_url: p.token_endpoint.clone(),
        session_label: None,
    };
    s.f.repo.upsert(&reg).await.unwrap();
    s.f.refresh().await;
    s.f.agents
        .update_policy(
            &s.agent,
            Some(Some(vec!["native".into()])),
            None,
            None,
            None,
        )
        .await
        .unwrap();
}
pub async fn runtime(s: &Setup, p: Profile, key: SealingKey) -> Runtime {
    let dir = s.f._dir.path();
    let cfg = Config {
        callback: Callback {
            address: "127.0.0.1:19294".parse().unwrap(),
            cert_path: dir.join("server.pem"),
            key_path: dir.join("server.key"),
        },
        profiles: vec![p],
    };
    let owner = Default::default();
    let consent = consent::Runtime::new(s.f.pool.clone(), key, cfg, owner)
        .await
        .unwrap();
    Runtime::new(
        s.f.repo.clone(),
        s.f.catalog.clone(),
        None,
        vec![],
        Default::default(),
    )
    .await
    .unwrap()
    .with_consent(Some(consent))
}
pub async fn setup() -> Setup {
    agent_locksmith::admin::https::install_crypto_provider_once();
    let mut s = Setup::new().await;
    let _ = pki::Pki::write(s.f._dir.path());
    let p = profile(s.f._dir.path(), 19293);
    configure(&s, &p).await;
    insert(&s, &p, &key(), "x", "owner").await;
    s.rt = runtime(&s, p, key()).await;
    s
}
pub async fn select(s: &Setup) {
    let view =
        s.rt.consent
            .as_ref()
            .unwrap()
            .account("owner", "native", "x")
            .await
            .unwrap();
    s.rt.select_oauth(
        "owner",
        &s.agent,
        "native",
        "x",
        view["revision"].as_str().unwrap(),
    )
    .await
    .unwrap();
}
