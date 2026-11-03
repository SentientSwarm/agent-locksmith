use crate::fixture::SENTINELS;
use agent_locksmith::app::build_app_full_with_phase_g;
use agent_locksmith::auth_v2::BearerAuthenticator;
use agent_locksmith::config::parse_config_str;
use agent_locksmith::registrations::{Catalog, RegistrationRepository};
use agent_locksmith::repo::audit::AuditRepository;
use agent_locksmith::repo::{AgentCredentialRepository, AgentRepository};
use arc_swap::ArcSwap;
use axum_test::TestServer;
use secrecy::SecretString;
use std::{collections::HashMap, sync::Arc};

pub fn server(
    agents: &AgentRepository,
    bindings: Option<AgentCredentialRepository>,
    registrations: &Arc<RegistrationRepository>,
    catalog: Arc<ArcSwap<Catalog>>,
    audit: AuditRepository,
) -> TestServer {
    let config = parse_config_str("listen:\n  host: 127.0.0.1\n  port: 9200\n").unwrap();
    let resolved = HashMap::from([("api".into(), SecretString::from(SENTINELS[2]))]);
    TestServer::new(build_app_full_with_phase_g(
        Arc::new(ArcSwap::from_pointee(config)),
        Some(audit.clone()),
        Arc::new(ArcSwap::from_pointee(resolved)),
        None,
        Some(Arc::new(
            BearerAuthenticator::with_audit(agents.clone(), Some(audit.clone())).unwrap(),
        )),
        Some(registrations.clone()),
        catalog.clone(),
        None,
        bindings,
    ))
}
