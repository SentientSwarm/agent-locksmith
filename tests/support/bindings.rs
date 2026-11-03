//! Explicit source selections for feature fixtures, never runtime migration.
use agent_locksmith::registrations::AuthSpec;
use agent_locksmith::repo::{AgentCredentialRepository, AgentRepository};
use sqlx::SqlitePool;

pub async fn select(
    agents: &AgentRepository,
    pool: &SqlitePool,
    public_id: &str,
    selections: &[(&str, AuthSpec)],
) -> AgentCredentialRepository {
    let id = agents
        .get_active_by_public_id(public_id)
        .await
        .unwrap()
        .unwrap()
        .id;
    let bindings = AgentCredentialRepository::new(pool.clone());
    for (name, spec) in selections {
        let mut spec = spec.clone();
        if let AuthSpec::OauthPkce { session_label, .. }
        | AuthSpec::OauthDeviceCode { session_label, .. } = &mut spec
        {
            *session_label = Some(session_label.clone().unwrap_or_else(|| "default".into()));
        }
        bindings.set(id, name, &spec).await.unwrap();
    }
    bindings
}
