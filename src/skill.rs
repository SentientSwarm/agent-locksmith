//! Optional-auth agent guidance from the same safe projection as /tools.
//! Fetching guidance neither materializes credentials nor contacts an upstream.
use crate::auth_v2::AgentIdentity;
use serde_json::Value;
mod personal;
#[cfg(test)]
mod tests;

const SKILL_TEMPLATE: &str = concat!(
    include_str!("skill_template.md"),
    "\n",
    include_str!("skill/native.md"),
    "\n",
    include_str!("skill/http.md"),
    "\n\n",
    include_str!("skill/http_repair.md"),
);

/// Generic, deployment-independent guidance. Certificate-only /skill is generic;
/// with Authorization present, existing listener authentication supplies identity.
pub fn render_unauthenticated() -> String {
    SKILL_TEMPLATE.to_string()
}

/// Safe caller-filtered discovery entries, including their protocol and path.
/// The caller performs the one shared catalog lookup; this renderer adds no authority.
pub fn render_authenticated(identity: &AgentIdentity, available: &[Value]) -> String {
    format!(
        "{}{}",
        SKILL_TEMPLATE,
        personal::render(identity, available)
    )
}
