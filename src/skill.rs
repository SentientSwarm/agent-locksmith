//! Agent-facing skill discovery (M9 / B1 follow-up).
//!
//! `GET /skill` returns a markdown document — formatted per the
//! [agentskills.io](https://agentskills.io) convention — that an agent
//! can paste into its LLM's system prompt to learn how to use this
//! locksmith deployment. Two forms:
//!
//! - **Unauthenticated** (`shutdown_signal`-skipped, like `/livez`): a
//!   generic protocol description. Authentication shape, endpoint
//!   catalog, error envelope, what-to-do-when-401-or-403. Deliberately
//!   does NOT leak tool names, descriptions, model identifiers, or any
//!   per-agent ACL — those are reserved for the personalized form so an
//!   unauthenticated probe learns no operational detail.
//! - **Authenticated** (`/skill` with a valid `Authorization: Bearer
//!   lk_…`): the generic content PLUS a personalized section listing
//!   the agent's name, public_id, exact ACL-resolved tool list with
//!   descriptions, and an audit-debug recipe scoped to the agent.
//!
//! The generic markdown is embedded at compile time via `include_str!`
//! so every binary ships with one canonical version. There is no
//! operator-override path — one source of truth.
//!
//! Routing is in `app::build_app_full`:
//! - Unauthenticated: `GET /skill` → `unauthenticated_skill` (added to
//!   the auth middleware skip list).
//! - Authenticated: `GET /agent/skill` → `authenticated_skill` (under
//!   the same middleware as `/api/...`, so the per-agent bearer is
//!   enforced and `AgentIdentity` is stamped into request extensions
//!   before the handler runs).

use crate::auth_v2::AgentIdentity;
use crate::config::AppConfig;
use crate::secret::ResolvedCreds;

/// The compile-time generic skill markdown. Returned as-is for
/// unauthenticated probes; appended to the personalized section for
/// authenticated requests.
const SKILL_TEMPLATE: &str = include_str!("skill_template.md");

/// Render the unauthenticated form: the embedded template, unchanged.
pub fn render_unauthenticated() -> String {
    SKILL_TEMPLATE.to_string()
}

/// Render the personalized form: the embedded template followed by a
/// "## Personalized for `<agent_name>`" section listing the agent's
/// resolved tool list (allowlist ∩ active tools, minus denylist) with
/// each tool's name + description, and an audit-debug recipe.
///
/// `config` and `resolved_creds` come from the live `AppState`; the
/// resolved tool list uses the same filtering as `/tools` (active tools
/// only) so the agent never sees a tool it would 403 on.
pub fn render_authenticated(
    identity: &AgentIdentity,
    config: &AppConfig,
    resolved_creds: &ResolvedCreds,
) -> String {
    let allowlist_str = identity
        .tool_allowlist
        .as_ref()
        .map(|v| format!("`[{}]`", v.join(", ")))
        .unwrap_or_else(|| "`(unrestricted — no allowlist set)`".to_string());
    let denylist_str = identity
        .tool_denylist
        .as_ref()
        .map(|v| format!("`[{}]`", v.join(", ")))
        .unwrap_or_else(|| "`(none)`".to_string());

    // Compute the effective tool catalog: each currently-active tool
    // that the agent's ACL permits. Mirrors `proxy::check_tool_acl`
    // semantics so this output exactly matches what the agent can
    // actually call.
    let effective: Vec<&crate::config::ToolConfig> = config
        .active_tools_against(resolved_creds)
        .into_iter()
        .filter(|t| identity.allows_tool(&t.name).is_ok())
        .collect();

    let mut tools_md = String::new();
    if effective.is_empty() {
        tools_md.push_str(
            "_No tools currently available to you._ Either your ACL excludes \
             every active tool, or no tools are active in this deployment. \
             Ask your operator to widen your allowlist or shrink your denylist.\n",
        );
    } else {
        tools_md.push_str("| Tool | Description |\n|---|---|\n");
        for tool in &effective {
            // Trim newlines from descriptions so the markdown table
            // stays well-formed even if operators wrote multi-line YAML.
            let desc = tool.description.replace('\n', " ");
            tools_md.push_str(&format!("| `{}` | {} |\n", tool.name, desc));
        }
    }

    let personalized = format!(
        r#"

---

## Personalized for `{name}`

You're authenticated as **{name}** (`public_id={public_id}`).

### Tools available to you right now

{tools_md}

To call one of these tools:

```
curl -fsS -H "Authorization: Bearer $LOCKSMITH_TOKEN" \
  http://<locksmith>/api/<tool>/<upstream-path>
```

The `<upstream-path>` is forwarded verbatim to the tool's upstream — for
example, `/api/{first_tool_or_placeholder}/v1/chat/completions` reaches the
upstream's `v1/chat/completions` endpoint. Locksmith strips your
`Authorization` header and injects the configured upstream credential
before forwarding.

### Your ACL

- **Allowlist**: {allowlist}
- **Denylist**: {denylist}

Both are managed by your operator via `locksmith agent modify
{public_id} --allowlist ... --denylist ...`. Re-fetch this skill after a
change to see the new tool list.

### Audit-debug recipe (operator-facing)

If you start getting 403 `tool_not_allowed`, your operator can trace:

```
locksmith audit query --event-class security --agent {public_id} \
  --since-ms <ms>
```

Recent denies for you appear with `event=authz_denied` and
`details.reason` set to either `not_in_allowlist` or `in_denylist`. 401s
appear with `event=auth_failure` and `details.reason` carrying the
specific failure mode (`missing_credential`, `malformed_token`,
`wrong_namespace`, `unknown_public_id`, `secret_mismatch`, `expired`).
"#,
        name = identity.name,
        public_id = identity.public_id,
        tools_md = tools_md,
        allowlist = allowlist_str,
        denylist = denylist_str,
        first_tool_or_placeholder = effective
            .first()
            .map(|t| t.name.as_str())
            .unwrap_or("<tool>"),
    );

    format!("{}{}", SKILL_TEMPLATE, personalized)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth_v2::AgentIdentity;
    use crate::config::parse_config_str;

    fn ident_with(name: &str, allow: Option<&[&str]>, deny: Option<&[&str]>) -> AgentIdentity {
        AgentIdentity {
            public_id: "TESTPID12345".into(),
            name: name.into(),
            tool_allowlist: allow.map(|s| s.iter().map(|t| t.to_string()).collect()),
            tool_denylist: deny.map(|s| s.iter().map(|t| t.to_string()).collect()),
        }
    }

    #[test]
    fn unauthenticated_form_is_the_template_unchanged() {
        let s = render_unauthenticated();
        assert_eq!(s, SKILL_TEMPLATE);
    }

    #[test]
    fn unauthenticated_form_has_no_tool_or_model_names() {
        // Operational hygiene: the unauth form must not leak tool
        // catalog or per-deployment model names. Operators rotate
        // tools / models without bumping this constant; keeping it
        // generic prevents an unauthenticated probe from learning the
        // active deployment shape.
        let s = render_unauthenticated();
        // Sanity: should NOT mention any specific tool or model that
        // a real deployment might configure (these strings appear in
        // typical configs but should not be in the embedded template).
        for forbidden in [
            "anthropic",
            "openai",
            "lmstudio",
            "ollama",
            "tavily",
            "github",
            "qwen",
            "claude",
            "gpt-4",
            "gemma",
        ] {
            assert!(
                !s.to_lowercase().contains(forbidden),
                "unauthenticated /skill must not mention any specific tool/model; \
                 found '{forbidden}' in template"
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
        let yaml = r#"
listen:
  host: "127.0.0.1"
  port: 9200
tools:
  - name: "things"
    description: "Things service"
    upstream: "http://example.invalid"
    timeouts: { request_seconds: 5, idle_seconds: 5 }
"#;
        let cfg = parse_config_str(yaml).unwrap();
        let resolved = crate::secret::resolve_tool_creds_sync_env_only(&cfg);
        let id = ident_with("agent-alpha", Some(&["things"]), None);
        let s = render_authenticated(&id, &cfg, &resolved);
        assert!(s.contains("agent-alpha"));
        assert!(s.contains("TESTPID12345"));
        // Tool table is rendered for tools the agent is allowed to call.
        assert!(s.contains("`things`"));
        assert!(s.contains("Things service"));
        // The unauth template is preserved verbatim at the top.
        assert!(s.starts_with(SKILL_TEMPLATE));
    }

    #[test]
    fn authenticated_form_filters_by_acl() {
        let yaml = r#"
listen:
  host: "127.0.0.1"
  port: 9200
tools:
  - name: "good"
    description: "Allowed tool"
    upstream: "http://example.invalid"
    timeouts: { request_seconds: 5, idle_seconds: 5 }
  - name: "bad"
    description: "Denied tool"
    upstream: "http://example.invalid"
    timeouts: { request_seconds: 5, idle_seconds: 5 }
"#;
        let cfg = parse_config_str(yaml).unwrap();
        let resolved = crate::secret::resolve_tool_creds_sync_env_only(&cfg);
        let id = ident_with("narrow-agent", Some(&["good"]), None);
        let s = render_authenticated(&id, &cfg, &resolved);
        assert!(s.contains("`good`"), "allowlist hit must appear");
        assert!(
            !s.contains("`bad`"),
            "tool not in allowlist must NOT appear in the personalized table"
        );
    }

    #[test]
    fn authenticated_form_handles_empty_acl_intersection() {
        let yaml = r#"
listen:
  host: "127.0.0.1"
  port: 9200
tools:
  - name: "things"
    description: "Things service"
    upstream: "http://example.invalid"
    timeouts: { request_seconds: 5, idle_seconds: 5 }
"#;
        let cfg = parse_config_str(yaml).unwrap();
        let resolved = crate::secret::resolve_tool_creds_sync_env_only(&cfg);
        // Allowlist references a tool that doesn't exist → empty
        // intersection → must render a friendly explainer rather than a
        // bare empty table.
        let id = ident_with("empty-agent", Some(&["nonexistent"]), None);
        let s = render_authenticated(&id, &cfg, &resolved);
        assert!(s.contains("No tools currently available to you"));
        assert!(!s.contains("`things`"));
    }
}
