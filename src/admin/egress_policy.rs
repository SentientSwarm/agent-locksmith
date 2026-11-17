//! AGENT-137 — the egress policy Locksmith wants enforced, published for
//! the egress proxy. Every host an enabled `proxied` route reaches,
//! including its OAuth token endpoints, with the routes behind it. The
//! proxy URL itself is never returned.

use super::uds::UdsState;
use crate::auth_v2::OperatorIdentity;
use crate::config::{EgressEnforcement, EgressMode};
use crate::registrations::{AuthSpec, Kind, RegistrationRepository};
use crate::repo::AgentCredentialRepository;
use axum::{
    Extension, Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::{Value, json};
use std::collections::BTreeMap;

/// `GET /admin/operator/egress/policy`.
/// With a registration repository the database is the authority on what
/// is served (D4), so YAML tools are used only on legacy deployments
/// without one. A failed read is an error, never a partial allowlist.
pub(super) async fn op_egress_policy(
    State(state): State<UdsState>,
    Extension(_op): Extension<OperatorIdentity>,
) -> Response {
    let config = state.admin.config_snapshot();
    let routes: Vec<(String, String)> = match &state.registrations {
        Some(repo) => match registration_routes(repo, state.agent_creds.as_ref()).await {
            Ok(routes) => routes,
            Err(()) => {
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(json!({ "error": { "code": "registrations_unavailable",
                        "message": "registrations could not be read; no partial policy is returned" } })),
                )
                    .into_response();
            }
        },
        None => config
            .tools
            .iter()
            .filter(|t| t.egress == EgressMode::Proxied)
            .map(|t| (t.name.clone(), t.upstream.clone()))
            .collect(),
    };
    let mode = config.egress_enforcement().map(|m| match m {
        EgressEnforcement::Pipelock => "pipelock",
        EgressEnforcement::External => "external",
    });
    Json(json!({
        "mode": mode,
        "egress_proxy_set": config.egress_proxy.is_some(),
        "hosts": hosts(&routes),
    }))
    .into_response()
}

/// `(route, url)` for every URL an enabled proxied route reaches: its
/// upstream and, for OAuth (AGENT-269), the token URL of the route and of
/// each agent binding that selects one for it. Read failures are logged.
/// `infra` rows are left out: no path calls their upstream.
async fn registration_routes(
    repo: &RegistrationRepository,
    bindings: Option<&AgentCredentialRepository>,
) -> Result<Vec<(String, String)>, ()> {
    let rows = repo.list(None).await.map_err(|e| {
        tracing::warn!(error = %e, "egress policy: registrations could not be read");
    })?;
    let proxied: Vec<_> = rows
        .into_iter()
        .filter(|r| !r.disabled && r.egress == EgressMode::Proxied && r.kind != Kind::Infra)
        .collect();
    let mut routes = Vec::new();
    for r in &proxied {
        routes.push((r.name.clone(), r.upstream.clone()));
        routes.extend(token_url(&r.auth).map(|u| (r.name.clone(), u)));
    }
    if let Some(bindings) = bindings {
        // A decode error can quote the stored row, so none is logged.
        let all = bindings.list_all().await.map_err(|_| {
            tracing::warn!("egress policy: agent bindings could not be read");
        })?;
        for b in all {
            if proxied.iter().any(|r| r.name == b.registration) {
                routes.extend(token_url(&b.auth_spec).map(|u| (b.registration, u)));
            }
        }
    }
    Ok(routes)
}

fn token_url(auth: &AuthSpec) -> Option<String> {
    crate::oauth::refresh::selected_parameters(auth).map(|(url, _)| url.to_string())
}

/// Group `(route, upstream)` pairs by destination host and port, sorted.
fn hosts(routes: &[(String, String)]) -> Value {
    let mut by_host: BTreeMap<(String, u16), Vec<String>> = BTreeMap::new();
    for (name, upstream) in routes {
        let Ok(url) = reqwest::Url::parse(upstream) else {
            continue;
        };
        let (Some(host), Some(port)) = (url.host_str(), url.port_or_known_default()) else {
            continue;
        };
        by_host
            .entry((host.to_ascii_lowercase(), port))
            .or_default()
            .push(name.clone());
    }
    Value::Array(
        by_host
            .into_iter()
            .map(|((host, port), mut routes)| {
                routes.sort();
                routes.dedup();
                json!({ "host": host, "port": port, "routes": routes })
            })
            .collect(),
    )
}

/// Render a policy document as a Pipelock `api_allowlist` fragment.
pub fn pipelock_allowlist(policy: &Value) -> String {
    let mut hosts: Vec<&str> = policy["hosts"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|h| h["host"].as_str())
        .collect();
    hosts.sort_unstable();
    hosts.dedup();
    // AGENT-269: a YAML emitter quotes whatever a host holds, so no host
    // can break or extend the document.
    let body = serde_yaml::to_string(&BTreeMap::from([("api_allowlist", hosts)]))
        .unwrap_or_else(|_| "api_allowlist: []\n".into());
    format!(
        "# Generated by `locksmith egress policy --pipelock`. Hosts reached by\n# Locksmith's proxied routes.\n{body}"
    )
}
