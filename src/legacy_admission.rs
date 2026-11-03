//! Diagnose legacy routes that cannot select an account for an actual agent.
use crate::{app::AppState, registrations::Kind};

pub(crate) const UPGRADE_MESSAGE: &str = "enable the admin database/listener, register an agent, authenticate with its bearer or mTLS identity, and explicitly select an account; a shared bearer cannot select an account";

pub(crate) fn credentialed(state: &AppState, name: &str) -> bool {
    if let Some(row) = state.catalog.load().lookup_active(name) {
        return row.auth.injects_header();
    }
    state
        .config
        .load()
        .tools
        .iter()
        .any(|t| t.name == name && t.auth.is_some())
}

pub(crate) fn incompatible_tools(state: &AppState) -> Vec<String> {
    if state.agent_auth.is_some() || state.mtls_authenticator.is_some() {
        return vec![];
    }
    let mut names: Vec<String> = state
        .config
        .load()
        .tools
        .iter()
        .filter(|t| t.auth.is_some())
        .map(|t| t.name.clone())
        .collect();
    let catalog = state.catalog.load();
    for kind in [Kind::Tool, Kind::Model] {
        names.extend(
            catalog
                .iter_enabled_by_kind(kind)
                .filter(|r| r.auth.injects_header())
                .map(|r| r.name.clone()),
        );
    }
    names.sort();
    names.dedup();
    names
}
