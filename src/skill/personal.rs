use crate::auth_v2::AgentIdentity;
use serde_json::Value;

pub(super) fn render(identity: &AgentIdentity, listing: &[Value]) -> String {
    let mut http = Vec::new();
    let mut native = Vec::new();
    let mut compact = Vec::new();
    for value in listing {
        let Some(entry) = entry(value) else { continue };
        match value["type"].as_str() {
            Some("api") if entry.2.starts_with("/api/") => http.push(entry),
            Some("mcp") if entry.2.starts_with("/mcp/") => {
                native.push(entry);
                if let Some(path) = value["compact_path"]
                    .as_str()
                    .filter(|p| p.starts_with("/mcp/") && p.ends_with("/compact"))
                {
                    compact.push((entry.0, entry.1, path));
                }
            }
            _ => {} // Unknown projection shapes are not an invitation to guess a route.
        }
    }
    let id = code(&identity.public_id);
    let name = display(&identity.name);
    let mut out = format!(
        "\n---\n\n## Personalized for `{name}`\n\nYou're authenticated as **{name}** (`public_id={id}`).\n\n### Tools eligible under your ACL\n\nThese are connections, not native callable-tool inventory.\n"
    );
    if http.is_empty() && native.is_empty() {
        out.push_str("\n_No tools currently available to you._ No eligible active connection is visible. Ask your operator to inspect current grants, catalog activation and intended policy.\n");
    }
    table(&mut out, "HTTP connections", &http);
    table(&mut out, "Native MCP connections", &native);
    table(&mut out, "Opt-in compact MCP connections", &compact);
    if !compact.is_empty() {
        out.push_str("\nFor an explicitly listed compact path: initialize, notifications/initialized, tools/list, search, full describe, then invoke with that handle and contract_digest. Decode search/describe JSON from the single text block. Never reuse a standard session on compact or automatically retry an ambiguous call through another route.\n");
    }
    out.push_str("\nThis list shows ACL eligibility, not account binding existence or source health.\nA listed connection can still refuse calls. Native tools/list may be empty even when the connection is visible.\n");
    if !http.is_empty() {
        out.push_str(
            r#"
### Call an HTTP connection

Choose the HTTP method, operation path, query/body and response type from the
optional http_service descriptor in authenticated /tools, or the service's
public API docs for legacy entries. Append the operation path to that entry's
public /api path. Do not infer a chat endpoint from the connection name.

```
curl -fsS -X <METHOD> -H "Authorization: Bearer $LOCKSMITH_TOKEN" \
  http://<locksmith>/api/<tool>/<upstream-path>
```

Use the operator's verified HTTPS listener for remote access. Locksmith strips
your Authorization and injects only the deliberately selected upstream credential.
"#,
        );
        if http.iter().any(|e| e.0 == "codex") {
            out.push_str(include_str!("codex.md"));
        }
        out.push_str(&include_str!("personal_http.md").replace("{{public_id}}", &id));
    }
    if !native.is_empty() {
        out.push_str(
            r#"
### Call a native MCP tool

Use the listed /mcp path and the native request sequence above. Initialize,
send notifications/initialized, then tools/list for complete public input/output
schemas before tools/call. Connection permission and selection do not grant a
tool. Construct only public arguments; protected fixed inputs are omitted.
Do not send HTTP service operations through /api for these connections.

### Native diagnosis (operator-facing)

Read local state first; these GET-backed commands do not contact an upstream:

```
"#,
        );
        out.push_str(&format!("locksmith --format json tool mcp show <connection> --agent {id}\nlocksmith --format json agent mcp-grants show <connection> --agent {id}\nlocksmith agent credentials list {id}\nlocksmith audit query --agent {id} --since-ms <ms>\n```\n"));
        out.push_str("\nUse the native repair steps above: current observation/review/grant and explicit None/live StoredBearer or owner-selected controlled OAuth, then a fresh session when needed. Controlled refresh changes authority and requires reobserve/review/regrant; reconnect also requires select-oauth. HTTP env/op/header/OAuth recipes do not apply. Missing outcomes remain unknown; do not replay or switch accounts.\n");
    }
    out.push_str(&format!(
        "\n### Connection policy\n\n- **Allowlist**: {}\n- **Denylist**: {}\n\nThese connection-level lists do not describe native tool grants. Native calls also require current per-agent reviewed contracts. Only your operator changes policy; re-fetch discovery after a deliberate change.\n",
        policy(identity.tool_allowlist.as_deref(), "(no connection grants)"),
        policy(identity.tool_denylist.as_deref(), "(none)"),
    ));
    out
}

fn entry(value: &Value) -> Option<(&str, &str, &str)> {
    Some((
        value.get("name")?.as_str()?,
        value
            .get("description")
            .and_then(Value::as_str)
            .unwrap_or(""),
        value.get("path")?.as_str()?,
    ))
}

fn table(out: &mut String, title: &str, entries: &[(&str, &str, &str)]) {
    if entries.is_empty() {
        return;
    }
    out.push_str(&format!(
        "\n#### {title}\n\n| Connection | Description | Public path |\n|---|---|---|\n"
    ));
    for (name, description, path) in entries {
        out.push_str(&format!(
            "| `{}` | {} | `{}` |\n",
            code(name),
            display(description),
            code(path)
        ));
    }
}

fn policy(values: Option<&[String]>, absent: &str) -> String {
    values
        .map(|v| {
            format!(
                "`[{}]`",
                v.iter().map(|s| code(s)).collect::<Vec<_>>().join(", ")
            )
        })
        .unwrap_or_else(|| format!("`{absent}`"))
}

/// Display untrusted catalog/identity text as one line, never Markdown structure.
fn display(value: &str) -> String {
    let mut out = String::new();
    for c in value.chars() {
        if c.is_control() || matches!(c, '\u{2028}'..='\u{202e}' | '\u{2066}'..='\u{2069}') {
            out.push(' ');
        } else if matches!(
            c,
            '&' | '<' | '>' | '|' | '`' | '*' | '_' | '[' | ']' | '\\'
        ) {
            out.push_str(&format!("&#{};", c as u32));
        } else {
            out.push(c);
        }
    }
    out
}

// Emphasis characters are literal inside code spans and command fences. Preserve
// generated public IDs (which can contain underscores) for executable repair.
fn code(value: &str) -> String {
    display(value).replace("&#95;", "_").replace("&#42;", "*")
}
