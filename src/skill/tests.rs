use super::*;
use crate::auth_v2::AgentIdentity;
use serde_json::{Value, json};

fn ident_with(name: &str, allow: Option<&[&str]>, deny: Option<&[&str]>) -> AgentIdentity {
    AgentIdentity {
        id: 0,
        public_id: "TESTPID12345".into(),
        name: name.into(),
        tool_allowlist: allow.map(|s| s.iter().map(|t| t.to_string()).collect()),
        tool_denylist: deny.map(|s| s.iter().map(|t| t.to_string()).collect()),
    }
}

fn tools(pairs: &[(&str, &str)]) -> Vec<Value> {
    pairs
        .iter()
        .map(|(n, d)| json!({"name":n,"description":d,"type":"api","path":format!("/api/{n}")}))
        .collect()
}

#[test]
fn unauthenticated_form_is_the_template_unchanged() {
    let s = render_unauthenticated();
    assert_eq!(s, SKILL_TEMPLATE);
}

#[test]
fn unauthenticated_form_does_not_leak_specific_model_ids() {
    // Operational hygiene: the unauth form must not leak per-
    // deployment model identifiers (specific models the operator
    // chose to load). It MAY reference well-known upstream
    // protocol patterns (anthropic, openai-compatible, codex)
    // because those are public protocol names, not deployment-
    // specific configuration — every locksmith deployment that
    // touches those upstreams looks the same shape.
    //
    // Hard line: model IDs (gpt-4, claude-opus, qwen-3.5,
    // gemma-3, llama-4) and operator-side env var names
    // (LM_API_KEY, ANTHROPIC_API_KEY) leak deployment shape and
    // must stay out of the template.
    let s = render_unauthenticated().to_lowercase();
    for forbidden in [
        "gpt-4",
        "gpt-3",
        "claude-opus",
        "claude-sonnet",
        "claude-haiku",
        "qwen3.",
        "qwen-3",
        "gemma-3",
        "gemma-4",
        "llama-3",
        "llama-4",
        "mistral-",
        "lm_api_key",
        "anthropic_api_key",
        "openai_api_key",
    ] {
        assert!(
            !s.contains(forbidden),
            "unauthenticated /skill must not mention deployment-specific \
                 model IDs or env var names; found '{forbidden}' in template"
        );
    }
}

#[test]
fn unauthenticated_form_advertises_personalized_form() {
    let s = render_unauthenticated();
    assert!(
        s.contains("personalized"),
        "unauth form must tell the caller about the authenticated form"
    );
    assert!(
        s.contains("Authorization: Bearer"),
        "unauth form must show the bearer auth shape so caller knows how to upgrade"
    );
}

#[test]
fn authenticated_form_includes_agent_name_and_public_id() {
    let id = ident_with("agent-alpha", Some(&["things"]), None);
    let available = tools(&[("things", "Things service")]);
    let s = render_authenticated(&id, &available);
    assert!(s.contains("agent-alpha"));
    assert!(s.contains("TESTPID12345"));
    // Tool table is rendered from the caller-provided list.
    assert!(s.contains("`things`"));
    assert!(s.contains("Things service"));
    // The unauth template is preserved verbatim at the top.
    assert!(s.starts_with(SKILL_TEMPLATE));
}

#[test]
fn authenticated_form_renders_tools_from_caller_provided_list() {
    // ACL filtering is the caller's responsibility (matches what
    // /tools does — `catalog_listing` applies the AgentIdentity
    // filter before returning). The renderer just emits whatever
    // it's given.
    let id = ident_with("narrow-agent", Some(&["good"]), None);
    let available = tools(&[("good", "Allowed tool")]);
    let s = render_authenticated(&id, &available);
    assert!(s.contains("`good`"), "tool in available list must appear");
    assert!(
        !s.contains("`bad`"),
        "tool not in available list must NOT appear in the personalized table"
    );
}

#[test]
fn authenticated_form_handles_empty_tool_list() {
    // Empty tool list (operator's allowlist excludes everything,
    // catalog is empty, etc.) → must render a friendly explainer
    // rather than a bare empty table.
    let id = ident_with("empty-agent", Some(&["nonexistent"]), None);
    let available: Vec<Value> = Vec::new();
    let s = render_authenticated(&id, &available);
    assert!(s.contains("No tools currently available to you"));
    assert!(!s.contains("`things`"));
}

#[test]
fn authenticated_form_codex_quirks_section_keyed_off_available_list() {
    // Phase G3 codex section appears when codex is in the agent's
    // available tools, regardless of whether it's also in allowlist
    // (the caller already filtered).
    let id = ident_with("codex-agent", Some(&["codex"]), None);
    let with_codex = tools(&[("codex", "OpenAI Responses API")]);
    let without_codex = tools(&[("wikipedia", "Wikipedia REST")]);
    assert!(render_authenticated(&id, &with_codex).contains("Codex quirks"));
    assert!(!render_authenticated(&id, &without_codex).contains("Codex quirks"));
}

#[test]
fn native_codex_does_not_receive_personalized_http_recipe() {
    let id = ident_with("agent", Some(&["codex"]), None);
    let listing =
        [json!({"name":"codex","description":"Native service","type":"mcp","path":"/mcp/codex"})];
    let s = render_authenticated(&id, &listing);
    let personal = s.split("## Personalized for").nth(1).unwrap();
    assert!(personal.contains("/mcp/codex"));
    assert!(!personal.contains("Codex quirks"));
    assert!(!personal.contains("/api/codex/responses"));
    assert!(!personal.contains("bearer=<ENV_VAR>"));
    assert!(personal.contains("tool mcp show"));
    assert!(personal.contains("agent mcp-grants show"));
}

#[test]
fn display_data_cannot_add_markdown_structure_or_unrelated_metadata() {
    let id = ident_with("agent`\n<script>", Some(&["a|b"]), None);
    let listing = [
        json!({"name":"odd`name","description":"line\r\n|[click](https://invalid) <b>*x*\\","type":"api","path":"/api/odd`name", "auth":{"value":"NEVER_RENDER_CUSTODY"},"metadata":{"private":"NEVER_RENDER_METADATA"}}),
    ];
    let s = render_authenticated(&id, &listing);
    let personal = s.split("## Personalized for").nth(1).unwrap();
    for forbidden in [
        "<script>",
        "<b>",
        "[click]",
        "*x*",
        "NEVER_RENDER_CUSTODY",
        "NEVER_RENDER_METADATA",
        "line\r\n|",
    ] {
        assert!(!personal.contains(forbidden), "{forbidden}");
    }
    assert!(personal.contains("odd&#96;name"));
    assert!(personal.contains("&#124;"));
    assert!(personal.contains("&#91;click&#93;"));
}

#[test]
fn incomplete_or_unknown_projection_does_not_get_a_guessed_recipe() {
    let id = ident_with("agent", None, None);
    let s = render_authenticated(
        &id,
        &[
            json!({"name":"missing-path","type":"api"}),
            json!({"name":"unknown-protocol","type":"future","path":"/future/unknown"}),
        ],
    );
    let personal = s.split("## Personalized for").nth(1).unwrap();
    assert!(!personal.contains("missing-path") && !personal.contains("unknown-protocol"));
    assert!(personal.contains("No tools currently available"));
}

#[test]
fn repair_commands_preserve_generated_public_id_underscores() {
    let mut id = ident_with("agent", Some(&["service"]), None);
    id.public_id = "generated_id_123".into();
    let body = render_authenticated(&id, &tools(&[("service", "HTTP")]));
    assert!(body.contains("locksmith agent credentials list generated_id_123"));
    assert!(!body.contains("generated&#95;"));
}
