# `/skill` reference

`GET /skill` is locksmith's auth-optional rendering surface — it
returns a markdown blob the calling agent can use to bootstrap its
tool catalog. Two rendering modes:

| Auth | Behavior | Cache |
|---|---|---|
| No `Authorization` header | Generic form (no tool/model leak) | `public, max-age=86400` |
| Valid agent bearer | Personalized form (this agent's tools, ACL, etc.) | `private, no-cache, no-store` |
| Invalid bearer | 401 (no silent downgrade) | n/a |

The auth-optional shape exists so a fresh agent can fetch a
"what is this proxy?" overview at startup without needing
credentials yet, while authenticated agents get an actionable
catalog.

## Wire shape

```http
GET /skill HTTP/1.1
Host: layer8.lan:9200
[Authorization: Bearer lk_...]   ← optional

HTTP/1.1 200 OK
Content-Type: text/markdown; charset=utf-8
Cache-Control: public, max-age=86400          ← when no bearer
Cache-Control: private, no-cache, no-store    ← when bearer

# layer8-proxy
...
```

## Generic (unauthenticated) form

Returned when no `Authorization` header is present. Same content
for every requester — no operational leak (no tool list, no agent
list, no version detail beyond what `/version` provides).

Sample (illustrative; the bundled content evolves with releases):

```markdown
# layer8-proxy

This is a **layer8-proxy** deployment — a credential proxy + ACL +
audit layer for AI agents.

To call a provider through this proxy, your agent needs a bearer
token. Operators issue bearers via:

  locksmith agent register --name <agent> --allowlist <tools>

With a valid bearer, the proxy exposes:

  GET  /tools                         — kind=tool catalog (ACL-filtered)
  GET  /models                        — kind=model catalog (ACL-filtered)
  ANY  /api/{tool_name}/{*path}       — proxy hot path

See your operator for an agent registration. The full operator-side
recipe lives at <https://github.com/SentientSwarm/layer8-proxy/blob/main/docs/user/getting-started.md>.

— layer8-proxy v1.0.0 / agent-locksmith v2.0.0
```

The generic form serves as a self-describing landing page. Useful
for human visitors hitting the URL in a browser, or for agents that
do a "what kind of endpoint is this?" probe before settling into a
session.

## Personalized (authenticated) form

Returned when a valid agent bearer is presented. Includes the
agent's specific tool catalog, ACL, audit-debug hints. Sample
(illustrative):

```markdown
# layer8-proxy: hermes-mini-m1

You are agent **hermes-mini-m1** (`yN2vR6jFKNYfIwNjFU2MSA`).

## Your allowlist

You can call:

  - **anthropic** — Anthropic Messages API
    POST /api/anthropic/v1/messages
  - **openai** — OpenAI Responses + Chat Completions API
    POST /api/openai/v1/chat/completions
  - **lmstudio** — LM Studio (on-host inference; optional bearer auth)
    POST /api/lmstudio/v1/chat/completions
  - **tavily** — Tavily search API
    POST /api/tavily/search

Tools NOT in your allowlist will return 403 tool_not_allowed.

## Wire contract

Send your bearer in the Authorization header:

  Authorization: Bearer lk_yN2vR6jFKNYfIwNjFU2MSA.<secret>

DO NOT send provider API keys. They're injected by the proxy.

## Audit & debugging

Operators can see your calls via:

  locksmith audit query --agent yN2vR6jFKNYfIwNjFU2MSA

If a call returns 503 oauth_refresh_failed, your operator needs to
re-bootstrap that OAuth session.

— hermes-mini-m1 / layer8-proxy v1.0.0
```

The personalized form is what agentskills.io–compatible tools can
ingest at startup to build their tool catalog without static config.

## Shape stability

The wire format (`Content-Type: text/markdown`) is stable across
v1.x. The content shape (headings, sections) is **not** stable — it
evolves as new features land. Agents that consume `/skill` should
parse it for "is this a layer8-proxy?" / "what can I call?" but
should NOT depend on specific markdown structure for parsing.

For machine-readable tool catalogs, use `GET /tools` + `GET /models`
(JSON, stable contract). `/skill` is the human / LLM-ingestible
overlay.

## Use cases

### LLM-driven agents

An agent's system prompt can include `GET /skill` output as
context — the LLM then knows what tools are available without
hardcoded config.

```python
# Pseudocode:
skill_md = httpx.get(
    "http://layer8.lan:9200/skill",
    headers={"Authorization": f"Bearer {locksmith_token}"}
).text

system_prompt = f"""
You are an AI agent. Your available tools and constraints:

{skill_md}

When you need a provider, call it through the proxy at the path
shown above.
"""
```

### Agent bootstrap discovery

A fresh agent at startup can:

1. `GET /skill` (no auth) → confirm this is a layer8-proxy + grab
   the generic info.
2. Look up its bearer (from env / token file).
3. `GET /skill` (with bearer) → grab the personalized catalog.
4. Use that catalog to populate its tool registry.

### Static documentation generation

Operators can run `curl http://localhost:9200/skill` against the
running daemon to generate up-to-date documentation for their
agent population — useful for runbooks.

## Cache headers

The `Cache-Control` distinction matters in practice:

| Form | Cache-Control | Why |
|---|---|---|
| Generic | `public, max-age=86400` | Same content for everyone; CDN-cacheable. |
| Personalized | `private, no-cache, no-store` | Per-agent content; ACL changes need to surface immediately. |

When operators modify an agent's ACL, the personalized `/skill` next
fetch reflects the change — no 24-hour cache to wait through.

## Streaming

`/skill` returns a complete markdown body (no streaming). Typical
size is 1–10 KB. For very large personalized catalogs (hundreds of
tools), consider whether you actually need them all in the agent's
context — `/tools` + `/models` JSON is more efficient for
machine-only consumers.

## Errors

| HTTP | When |
|---|---|
| 200 | Always when content rendered (generic OR personalized). |
| 401 | Bearer present but invalid. |
| 5xx | Daemon problem (rare). |

Note there's no 404 — `/skill` is always served.

## Implementation reference

The handler is `app::skill_handler` in `src/app.rs`. Generic
content lives in `src/skill_template.md`; personalized rendering is
`src/skill.rs::render_authenticated`.

To customize the generic content for a forked deployment: edit
`src/skill_template.md` + rebuild. To customize personalized
rendering: extend `skill::render_authenticated` (it has access to
`AgentIdentity` + `AppConfig` + `ResolvedCreds`).

## See also

- [wire-contract.md](wire-contract.md) — full wire surface (more
  than just `/skill`).
- [openclaw.md](openclaw.md), [hermes.md](hermes.md) — agent-specific
  recipes.
- [agentskills.io](https://agentskills.io) — the markdown-skill
  format `/skill` is loosely compatible with.
