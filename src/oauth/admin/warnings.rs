use super::*;

/// Returns operator-visible warnings about other labels under the
/// same registration that may have been invalidated upstream.
pub(super) async fn collision_warnings(
    state: &OauthAdminState,
    name: &str,
    bootstrapped_label: &str,
) -> Vec<String> {
    let mut out = Vec::new();
    let Ok(rows) = state.sessions.list_all().await else {
        return out;
    };
    let other_labels: Vec<String> = rows
        .into_iter()
        .filter(|(n, l, _, _, _)| n == name && l != bootstrapped_label)
        .map(|(_, l, _, _, _)| l)
        .collect();
    if !other_labels.is_empty() {
        out.push(format!(
            "Registration `{name}` already has session label(s): {labels}. \
             If those sessions point at the same upstream account as \
             label `{bootstrapped_label}`, the provider has likely \
             invalidated the prior refresh tokens (single-grant OAuth \
             policy on OpenAI ChatGPT, GitHub, Google, etc.). \
             Per-agent OAuth requires distinct upstream accounts; see \
             concepts/per-agent-credentials.md.",
            labels = other_labels.join(", "),
        ));
    }
    out
}
