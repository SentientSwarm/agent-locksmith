//! Explicit per-agent admission using the existing override repository (D1.1).
use super::*;
use crate::auth_v2::AgentIdentity;

pub(super) enum Failure {
    IdentityRequired,
    Missing,
    StoreUnavailable,
    CredentialUnavailable,
}

pub(super) async fn apply(
    state: &AppState,
    target: &mut ProxyTarget,
    extensions: &axum::http::Extensions,
) -> Result<(), Failure> {
    // Only explicitly authless targets may proceed without an agent identity.
    let Some(identity) = extensions.get::<AgentIdentity>() else {
        return if matches!(target.auth, ProxyAuth::None) {
            Ok(())
        } else {
            Err(Failure::IdentityRequired)
        };
    };
    let repo = state
        .agent_creds
        .as_ref()
        .ok_or(Failure::StoreUnavailable)?;
    let row = repo
        .get(identity.id, &target.name)
        .await
        // Do not log repository/parse error text: corrupt AuthSpec can contain
        // credential bytes. Only the classified cause reaches audit or wire.
        .map_err(|_| Failure::StoreUnavailable)?
        .ok_or(Failure::Missing)?;
    apply_spec(target, row.auth_spec)?;
    target.auth_source = "agent_override";
    Ok(())
}

fn selected_env(name: &str) -> Result<secrecy::SecretString, Failure> {
    std::env::var(name)
        .ok()
        .filter(|v| !v.is_empty())
        .map(secrecy::SecretString::from)
        .ok_or(Failure::CredentialUnavailable)
}

fn apply_spec(target: &mut ProxyTarget, spec: AuthSpec) -> Result<(), Failure> {
    target.auth = match spec {
        AuthSpec::None => ProxyAuth::None,
        AuthSpec::Header { header, env_var } => ProxyAuth::Header {
            header,
            audit_mode: "header",
            override_value: Some(selected_env(&env_var)?),
        },
        AuthSpec::Bearer { env_var } => ProxyAuth::Bearer {
            override_value: Some(selected_env(&env_var)?),
        },
        other => return apply_custody_spec(target, other),
    };
    Ok(())
}

// Materialize only the explicitly selected source and mechanism.
fn apply_custody_spec(target: &mut ProxyTarget, spec: AuthSpec) -> Result<(), Failure> {
    match spec {
        AuthSpec::StoredHeader { header, secret_ref } => {
            target.auth = stored(Some(header), secret_ref, "stored_header");
        }
        AuthSpec::StoredBearer { secret_ref } => {
            target.auth = stored(None, secret_ref, "stored_bearer");
        }
        AuthSpec::OpHeader { header, reference } => {
            target.auth = op(Some(header), reference, "op_header");
        }
        AuthSpec::OpBearer { reference } => {
            target.auth = op(None, reference, "op_bearer");
        }
        spec @ (AuthSpec::OauthPkce { .. } | AuthSpec::OauthDeviceCode { .. }) => {
            apply_oauth(target, spec)?;
        }
        _ => unreachable!("env and no-auth handled before custody"),
    }
    Ok(())
}

fn stored(header: Option<String>, secret_ref: String, audit_mode: &'static str) -> ProxyAuth {
    ProxyAuth::Stored {
        header,
        audit_mode,
        secret_ref,
        resolved_value: None,
    }
}

fn op(header: Option<String>, reference: String, audit_mode: &'static str) -> ProxyAuth {
    ProxyAuth::Op {
        header,
        audit_mode,
        reference,
        resolved_value: None,
    }
}

pub(super) async fn record_failure(
    audit: &Option<AuditRepository>,
    ctx: &RequestCtx,
    failure: Failure,
) -> Response {
    match failure {
        Failure::IdentityRequired => {
            let mut event = ctx.audit_event_base();
            event.event_class = EventClass::Security;
            event.event = "authz_denied".into();
            event.status = Some(401);
            event.decision = Decision::Denied;
            event.details = Some(json!({"reason":"agent_identity_required"}));
            audit_record(audit, event).await;
            (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error":{
                    "type":"auth_error", "code":"agent_identity_required",
                    "message": crate::legacy_admission::UPGRADE_MESSAGE,
                }})),
            )
                .into_response()
        }
        Failure::Missing => record_authz_denied(audit, ctx, "account_binding_missing").await,
        other => {
            let cause = match other {
                Failure::StoreUnavailable => "account_binding_unavailable",
                _ => "selected_credential_unavailable",
            };
            record_stored_unavailable(audit, ctx, cause).await;
            stored_unavailable_envelope("selected account credential is unavailable")
        }
    }
}

fn apply_oauth(target: &mut ProxyTarget, spec: AuthSpec) -> Result<(), Failure> {
    if crate::oauth::refresh::selected_parameters(&spec).is_none() {
        return Err(Failure::CredentialUnavailable);
    }
    let label = spec
        .oauth_session_label()
        .filter(|s| !s.trim().is_empty())
        .ok_or(Failure::CredentialUnavailable)?
        .to_string();
    let audit_mode = if matches!(spec, AuthSpec::OauthPkce { .. }) {
        "oauth_pkce"
    } else {
        "oauth_device_code"
    };
    target.oauth_session_label = Some(label);
    target.oauth_selection = Some(spec);
    target.auth = ProxyAuth::Oauth {
        audit_mode,
        oauth_session_id: String::new(),
        access_token: None,
        account_id: None,
    };
    Ok(())
}

// Check inside the existing session lock, before unsealing even cached tokens.
pub(super) async fn oauth_consistent(state: &AppState, target: &ProxyTarget, label: &str) -> bool {
    let (Some(bindings), Some(spec)) = (&state.agent_creds, &target.oauth_selection) else {
        return false;
    };
    matches!(crate::oauth::refresh::selected_source(bindings, &target.name, label).await,
        Ok(Some(current)) if &current == spec)
}
