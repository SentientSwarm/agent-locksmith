use serde_json::{Value, json};

pub(super) fn describe(observation: &Value, grants: usize, unavailable: Option<&str>) -> Value {
    let (state, repair) = match unavailable {
        Some("observation_required") => ("observation_required", "observe_then_review"),
        Some(_) => ("authority_unavailable", "inspect_selection_and_review"),
        None if observation["fresh"] != true => ("observation_required", "observe_then_review"),
        None if grants == 0 => ("ungranted", "review_then_replace_grants"),
        None => ("grant_current", "list_in_fresh_session"),
    };
    json!({"state":state,"repair_code":repair,"context_profile":"fixed-top-level-v1",
        "credential_readiness":"not_checked","provider_readiness":"unverified",
        "requires_session_list":true,"missing_outcome":"unknown"})
}
