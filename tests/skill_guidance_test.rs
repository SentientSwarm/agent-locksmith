use agent_locksmith::{auth_v2::AgentIdentity, skill::render_authenticated};

fn personal() -> String {
    let identity = AgentIdentity {
        id: 1,
        public_id: "test-caller".into(),
        name: "reference-consumer".into(),
        tool_allowlist: Some(vec!["reference-ledger".into()]),
        tool_denylist: None,
    };
    render_authenticated(
        &identity,
        &[
            serde_json::json!({"name":"reference-ledger","description":"Text account check","type":"api","path":"/api/reference-ledger"}),
        ],
    )
}

#[test]
fn authenticated_guidance_does_not_call_itself_generic() {
    let skill = personal();
    assert!(skill.contains("You're authenticated as **reference-consumer**"));
    assert!(!skill.contains("This document is the **generic** form"));
}

#[test]
fn personalized_guidance_does_not_invent_a_service_operation() {
    let skill = personal();
    assert!(skill.contains("| `reference-ledger` | Text account check |"));
    assert!(!skill.contains("/api/reference-ledger/v1/chat/completions"));
    assert!(skill.contains("http_service"));
}
