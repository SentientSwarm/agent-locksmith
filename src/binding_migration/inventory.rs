use super::{Error, digest, legacy, now, sources, types::*};
use crate::auth_v2::AgentIdentity;

// ponytail: offline scans of current routes; add lookup maps if inventory size makes preview costly.
pub(super) fn plan(s: &Snapshot, legacy: Vec<Legacy>) -> Result<Plan, Error> {
    let mut entries = Vec::new();
    for agent in &s.agents {
        for registration in &s.registrations {
            entries.push(entry(s, agent, registration, &legacy));
        }
    }
    // Preserve orphaned explicit rows too; never discard an unavailable choice.
    for b in &s.bindings {
        if !s.registrations.iter().any(|r| r.name == b.registration)
            || !s.agents.iter().any(|a| a.id == b.agent_id)
        {
            entries.push(Entry {
                agent_id: b.agent_id,
                registration: b.registration.clone(),
                action: "preserve".into(),
                reason: "missing_agent_or_registration_owner_mapping_required".into(),
                auth_spec: b.auth.clone(),
                selected: false,
            });
        }
    }
    entries.sort_by(|a, b| (a.agent_id, &a.registration).cmp(&(b.agent_id, &b.registration)));
    finish(s, entries, legacy)
}
fn finish(s: &Snapshot, entries: Vec<Entry>, legacy: Vec<Legacy>) -> Result<Plan, Error> {
    Ok(Plan {
        format_version: 1, snapshot: digest(s)?, agents: s.agents.clone(), entries, legacy,
        registrations: s.registrations.iter().map(|r| RegistrationSummary {
            name: r.name.clone(), kind: r.kind.clone(), disabled: r.disabled,
            auth_spec: r.auth.clone(),
        }).collect(),
        notice: "Offline reference metadata only; stop daemon for cutover. Credential values, keys and provider availability have NOT been verified. Change only selected flags on proposed rows; unresolved/config-only routes require owner mapping and real agent authentication.".into(),
    })
}

fn entry(s: &Snapshot, a: &Agent, r: &Registration, legacy: &[Legacy]) -> Entry {
    let existing = s
        .bindings
        .iter()
        .find(|b| b.agent_id == a.id && b.registration == r.name);
    let auth = match existing {
        Some(b) => b.auth.clone(),
        None => r.auth.clone().map(sources::inherited),
    };
    let source = auth
        .as_ref()
        .map(|spec| sources::reason(s, &r.name, spec))
        .unwrap_or("unsupported_or_malformed_source_owner_mapping_required");
    let blocked = route_reason(a, r).or_else(|| {
        existing
            .is_none()
            .then(|| legacy::mapping_reason(legacy, r))
            .flatten()
    });
    let (action, reason) = classify(existing.is_some(), source, blocked);
    Entry {
        agent_id: a.id,
        registration: r.name.clone(),
        action: action.into(),
        reason: reason.into(),
        auth_spec: auth,
        selected: false,
    }
}
pub(super) fn route_reason(a: &Agent, r: &Registration) -> Option<&'static str> {
    if a.revoked_at.is_some() {
        return Some("agent_revoked");
    }
    if a.expires_at.is_some_and(|t| t < now()) {
        return Some("agent_expired");
    }
    if r.disabled {
        return Some("registration_disabled");
    }
    let identity = AgentIdentity {
        id: a.id,
        public_id: a.public_id.clone(),
        name: a.name.clone(),
        tool_allowlist: a.tool_allowlist.clone(),
        tool_denylist: a.tool_denylist.clone(),
    };
    identity.allows_tool(&r.name).err()
}
pub(super) fn validate_selected(s: &Snapshot, p: &Plan) -> Result<(), Error> {
    for row in p.entries.iter().filter(|e| e.selected) {
        let a = s
            .agents
            .iter()
            .find(|a| a.id == row.agent_id)
            .ok_or(Error::Conflict)?;
        let r = s
            .registrations
            .iter()
            .find(|r| r.name == row.registration)
            .ok_or(Error::Conflict)?;
        let spec = row.auth_spec.as_ref().ok_or(Error::Conflict)?;
        if row.action != "propose"
            || route_reason(a, r).is_some()
            || !sources::usable(sources::reason(s, &r.name, spec))
        {
            return Err(Error::Conflict);
        }
    }
    Ok(())
}

fn classify(
    existing: bool,
    source: &'static str,
    blocked: Option<&'static str>,
) -> (&'static str, &'static str) {
    let reason = if !sources::usable(source) {
        source
    } else {
        blocked.unwrap_or(source)
    };
    let action = if existing {
        "preserve"
    } else if blocked.is_none() && sources::usable(source) {
        "propose"
    } else {
        "skip"
    };
    (action, reason)
}
