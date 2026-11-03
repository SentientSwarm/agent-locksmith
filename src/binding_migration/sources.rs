use super::types::*;
use crate::{
    oauth::refresh::{consensus, selected_parameters},
    registrations::AuthSpec,
};

/// Metadata evidence only. "unverified" never promises credential availability.
pub(super) fn reason(s: &Snapshot, name: &str, spec: &AuthSpec) -> &'static str {
    match spec {
        AuthSpec::None => "credential_free_explicit_selection",
        AuthSpec::Header { header, env_var } if valid_header(header) && valid_env(env_var) => {
            "env_value_unverified"
        }
        AuthSpec::Bearer { env_var } if valid_env(env_var) => "env_value_unverified",
        AuthSpec::OpHeader { header, .. } if !valid_header(header) => "invalid_source_reference",
        AuthSpec::OpHeader { .. } | AuthSpec::OpBearer { .. } => {
            if spec.validate_op_reference().is_ok() {
                "op_value_unverified"
            } else {
                "invalid_source_reference"
            }
        }
        AuthSpec::StoredHeader { header, .. } if !valid_header(header) => {
            "invalid_source_reference"
        }
        AuthSpec::StoredHeader { secret_ref, .. } | AuthSpec::StoredBearer { secret_ref } => {
            stored(s, secret_ref)
        }
        _ if spec.is_oauth() => oauth(s, name, spec),
        _ => "invalid_source_reference",
    }
}
pub(super) fn usable(reason: &str) -> bool {
    matches!(
        reason,
        "credential_free_explicit_selection"
            | "env_value_unverified"
            | "op_value_unverified"
            | "sealed_value_unverified"
            | "oauth_session_metadata_only"
    )
}
fn valid_env(name: &str) -> bool {
    // Match the OS environment namespace, not shell assignment syntax.
    !name.is_empty() && !name.contains(['=', '\0'])
}

fn valid_header(name: &str) -> bool {
    reqwest::header::HeaderName::from_bytes(name.as_bytes()).is_ok()
}
fn oauth(s: &Snapshot, name: &str, spec: &AuthSpec) -> &'static str {
    let Some(label) = spec.oauth_session_label().filter(|s| !s.trim().is_empty()) else {
        return "oauth_owner_reselection_required";
    };
    if selected_parameters(spec).is_none() {
        return "oauth_owner_reselection_required";
    }
    if let Err(reason) = consistency(s, name, spec, label) {
        return reason;
    }
    match s
        .sessions
        .iter()
        .find(|r| r.name == name && r.session_label == label)
    {
        Some(session) if !session.degraded => "oauth_session_metadata_only",
        Some(_) => "degraded_oauth_session",
        None => "missing_oauth_session",
    }
}
pub(super) fn inherited(mut spec: AuthSpec) -> AuthSpec {
    match &mut spec {
        AuthSpec::OauthPkce { session_label, .. }
        | AuthSpec::OauthDeviceCode { session_label, .. }
            if session_label.is_none() =>
        {
            *session_label = Some(crate::oauth::session::DEFAULT_SESSION_LABEL.into());
        }
        _ => {}
    }
    spec
}

fn stored(s: &Snapshot, secret_ref: &str) -> &'static str {
    if s.stored
        .iter()
        .any(|r| r.secret_ref == secret_ref && r.tombstoned_at.is_none())
    {
        "sealed_value_unverified"
    } else {
        "missing_or_tombstoned_stored_source"
    }
}

fn consistency(s: &Snapshot, name: &str, spec: &AuthSpec, label: &str) -> Result<(), &'static str> {
    // Runtime selected_source/list_all fails closed on any malformed override.
    if s.bindings.iter().any(|b| b.auth.is_none()) {
        return Err("oauth_selection_metadata_unavailable");
    }
    let relevant = s
        .bindings
        .iter()
        .filter(|b| b.registration == name)
        .filter_map(|b| b.auth.as_ref())
        .filter(|a| a.oauth_session_label() == Some(label));
    consensus(relevant.chain(std::iter::once(spec)))
        .map(|_| ())
        .map_err(|_| "conflicting_oauth_session_metadata")
}
