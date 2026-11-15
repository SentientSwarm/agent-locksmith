//! AGENT-253: secret-free audit rows for operator authority changes.
//!
//! Grants (`agent_modify`) record each changed field's before and after
//! value. Binding changes (`agent_credential_set` / `_unset`) record the
//! route and the binding kind. A binding summary carries only the kind,
//! the header name, the OAuth session label and an opaque stored ref,
//! never an env-var value, an `op://` reference or a credential.

use super::service::{AdminService, ModifyAgentInput};
use crate::auth_v2::OperatorIdentity;
use crate::registrations::AuthSpec;
use crate::repo::AgentRecord;
use crate::repo::audit::{AuditEvent, Decision, EventClass};
use serde_json::{Value, json};

/// One binding change, as it reaches the audit row.
pub(crate) struct BindingChange<'a> {
    pub agent_public_id: &'a str,
    pub registration: &'a str,
    pub binding: Option<&'a AuthSpec>,
    pub previous: Option<&'a AuthSpec>,
    pub error: Option<String>,
}

/// Secret-free description of a binding.
pub(crate) fn binding_summary(spec: &AuthSpec) -> Value {
    let kind = serde_json::to_value(spec)
        .ok()
        .and_then(|v| v.get("kind").cloned())
        .unwrap_or(Value::Null);
    let mut out = json!({ "kind": kind });
    if let Some(header) = spec.header_name() {
        out["header"] = header.into();
    }
    let label = match spec {
        AuthSpec::ControlledOauth { session_label, .. } => Some(session_label.as_str()),
        other => other.oauth_session_label(),
    };
    if let Some(label) = label {
        out["session_label"] = label.into();
    }
    if let Some(secret_ref) = spec.stored_secret_ref() {
        out["secret_ref"] = secret_ref.into();
    }
    out
}

/// Before/after for each field `input` changes. Metadata is recorded as
/// changed, not by value: it is free-form and may hold anything.
pub(crate) fn modify_details(before: Option<&AgentRecord>, input: &ModifyAgentInput) -> Value {
    let mut out = json!({});
    if let Some(after) = &input.allowlist {
        out["allowlist"] = json!({
            "before": before.and_then(AgentRecord::effective_allowlist),
            "after": after.clone().unwrap_or_default(),
        });
    }
    if let Some(after) = &input.denylist {
        out["denylist"] = json!({
            "before": before.and_then(|r| r.tool_denylist.clone()),
            "after": after,
        });
    }
    if let Some(after) = &input.expires_at {
        out["expires_at"] = json!({ "before": before.and_then(|r| r.expires_at), "after": after });
    }
    if input.metadata.is_some() {
        out["metadata"] = json!({ "changed": true });
    }
    out
}

impl AdminService {
    /// Record one binding change as an operator-class row.
    pub(crate) async fn audit_binding(
        &self,
        op: &OperatorIdentity,
        event: &str,
        change: BindingChange<'_>,
    ) {
        let mut details = json!({ "registration": change.registration });
        if let Some(binding) = change.binding {
            details["binding"] = binding_summary(binding);
        }
        if let Some(previous) = change.previous {
            details["previous"] = binding_summary(previous);
        }
        if let Some(error) = &change.error {
            details["error"] = error.as_str().into();
        }
        self.audit_for_operator(
            op,
            AuditEvent {
                ts_ms: super::service::now_ms(),
                event_class: EventClass::Operator,
                event: event.into(),
                agent_public_id: Some(change.agent_public_id.to_string()),
                tool: Some(change.registration.to_string()),
                decision: if change.error.is_none() {
                    Decision::Allowed
                } else {
                    Decision::Denied
                },
                details: Some(details),
                ..AuditEvent::default()
            },
        )
        .await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summary_omits_env_var_and_op_reference() {
        let env = AuthSpec::Bearer {
            env_var: "SECRET_ENV_NAME".into(),
        };
        let op = AuthSpec::OpHeader {
            header: "x-api-key".into(),
            reference: "op://vault/item/field".into(),
        };
        assert_eq!(binding_summary(&env), json!({ "kind": "bearer" }));
        assert_eq!(
            binding_summary(&op),
            json!({ "kind": "op_header", "header": "x-api-key" })
        );
    }

    #[test]
    fn summary_names_broker_and_oauth_label() {
        assert_eq!(
            binding_summary(&AuthSpec::Broker),
            json!({ "kind": "broker" })
        );
        let oauth = AuthSpec::OauthDeviceCode {
            client_id: "c".into(),
            scopes: vec![],
            device_url: "https://d".into(),
            token_url: "https://t".into(),
            session_label: Some("jxs".into()),
        };
        assert_eq!(binding_summary(&oauth)["session_label"], "jxs");
    }
}
