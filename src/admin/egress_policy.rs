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
            Err((code, what)) => {
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(json!({ "error": { "code": code,
                        "message": format!("{what} could not be read; no partial policy is returned") } })),
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
/// each agent binding that selects one for it. Read failures are logged
/// and returned as `(error code, what failed)`.
/// `infra` rows are left out: no path calls their upstream.
async fn registration_routes(
    repo: &RegistrationRepository,
    bindings: Option<&AgentCredentialRepository>,
) -> Result<Vec<(String, String)>, (&'static str, &'static str)> {
    let rows = repo.list(None).await.map_err(|e| {
        tracing::warn!(error = %e, "egress policy: registrations could not be read");
        ("registrations_unavailable", "registrations")
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
            ("bindings_unavailable", "agent bindings")
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

/// The emitter writes YAML 1.2, where only `true`/`false` are booleans.
/// A YAML 1.1 parser also reads `yes`, `no`, `on`, `off`, `y` and `n` (any
/// case) as booleans, so quote list items spelled that way (AGENT-302).
/// The emitter leaves them plain, so each is a whole `- word` line.
fn quote_yaml_1_1_booleans(body: &str) -> String {
    const WORDS: [&str; 6] = ["yes", "no", "on", "off", "y", "n"];
    body.split_inclusive('\n')
        .map(|line| match line.trim_end().strip_prefix("- ") {
            Some(item) if WORDS.iter().any(|w| item.eq_ignore_ascii_case(w)) => {
                format!("- '{item}'\n")
            }
            _ => line.to_string(),
        })
        .collect()
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
    let body = quote_yaml_1_1_booleans(&body);
    format!(
        "# Generated by `locksmith egress policy --pipelock`. Hosts reached by\n# Locksmith's proxied routes.\n{body}"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// AGENT-302: a single-label host spelled like a YAML 1.1 boolean is
    /// quoted, so a 1.1 parser reads it as the host, not `true`/`false`.
    #[test]
    fn yaml_1_1_boolean_words_are_quoted() {
        let words = [
            "yes", "no", "on", "off", "y", "n", "Yes", "NO", "On", "OFF", "true", "False",
        ];
        let hosts: Vec<_> = words.iter().map(|w| json!({ "host": w })).collect();
        let out = pipelock_allowlist(&json!({ "hosts": hosts }));
        for w in words {
            assert!(
                out.contains(&format!("- '{w}'\n")) || out.contains(&format!("- \"{w}\"\n")),
                "{w} unquoted in:\n{out}"
            );
        }
        let plain = pipelock_allowlist(&json!({ "hosts": [{ "host": "api.example.com" }] }));
        assert!(plain.contains("- api.example.com\n"), "{plain}");
    }
}
