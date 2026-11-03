use super::fixture::Store;
use agent_locksmith::app::{OauthRuntime, build_app_full_with_phase_g};
use agent_locksmith::auth_v2::{AgentAuthenticator, BearerAuthenticator};
use agent_locksmith::config::parse_config_str;
use agent_locksmith::registrations::Catalog;
use arc_swap::ArcSwap;
use axum_test::TestServer;
use secrecy::SecretString;
use std::{collections::HashMap, sync::Arc};

pub fn app(
    store: &Store,
    catalog: Arc<ArcSwap<Catalog>>,
    oauth: Option<OauthRuntime>,
) -> TestServer {
    let auth: Arc<dyn AgentAuthenticator> =
        Arc::new(BearerAuthenticator::new(store.agents.clone()).unwrap());
    let config = parse_config_str("listen:\n  host: 127.0.0.1\n  port: 9200\n").unwrap();
    let resolved = HashMap::from([("proof".into(), SecretString::from("proof-default"))]);
    TestServer::new(build_app_full_with_phase_g(
        Arc::new(ArcSwap::from_pointee(config)),
        None,
        Arc::new(ArcSwap::from_pointee(resolved)),
        None,
        Some(auth),
        Some(store.registrations.clone()),
        catalog,
        oauth,
        Some(store.overrides.clone()),
    ))
}
