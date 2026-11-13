# Wire contract (agent-developer reference)

What an agent sees when calling locksmith. Use this as the spec for
wiring any agent (hermes, openclaw, or your own) through a layer8-proxy
deployment.

## Authentication

Every agent-facing endpoint (except `/livez`, `/readyz`, `/version`,
`/skill`) requires a bearer token in the `Authorization` header:

```
Authorization: Bearer lk_<22-char-public-id>.<43-char-secret>
```

The bearer is issued by the operator via `locksmith agent register`
(see [add-an-agent.md](https://github.com/SentientSwarm/layer8-proxy/blob/main/docs/user/add-an-agent.md)).
It identifies the agent and carries its ACL — the agent NEVER sends
provider API keys. Locksmith strips agent-supplied
`Authorization` / `x-api-key` / `host` headers before forwarding
upstream.

For mTLS-deployed agents (`auth_mode: mtls | both`), the bearer
is replaced by a client certificate; the cert's CN/SAN/URI maps to an
agent record.

Native entries use the separately bounded [MCP interface](native-mcp.md),
require current registered identity and never route through `/api`. Manual
None/live StoredBearer connections support explicitly reviewed per-tool grants
and committed dispatch; connection visibility alone grants no tool authority.
An opted-in [compact facade](compact-mcp.md) uses the same authority and dispatcher.
[Owner-selected controlled OAuth](../operator/native-oauth.md) uses the same finite
workflow. Supported local definition-backed connections use the separate
[operator activation workflow](../operator/integration-definitions.md) before
account and tool authority are granted. Hosted provider adoption remains outside
this bounded profile.
Existing HTTP behavior below is preserved.

## Endpoints

### `GET /livez` — liveness

```
HTTP 200 application/json
{"status": "live", "uptime_seconds": 3600}
```

Unauthenticated. Use as a Kubernetes liveness probe.

### `GET /readyz` — readiness

```
HTTP 200 application/json
{"status": "ready", "uptime_seconds": 3600}
```

Or, when any tool with auth has unresolved credentials:

```
HTTP 503 application/json
{"status": "not_ready", "reason": "tool_credentials_unresolved", "tools": ["foo", "bar"]}
```

Unauthenticated. Use as a Kubernetes readiness probe / orchestrator
gate. It is not a per-agent binding/source-health probe.

### `GET /version` — build metadata

```
HTTP 200 application/json
{"name": "agent-locksmith", "version": "2.0.0"}
```

Unauthenticated.

### `GET /skill` — agent skill rendering

Auth-optional. With a valid agent bearer, returns a personalised
markdown blob describing the agent's catalog (its allowed tools,
ACL, audit-debug recipes). Without a bearer, returns a generic
form (no operational leak — same content for every requester).

```
HTTP 200 text/markdown; charset=utf-8
Cache-Control: private, no-cache, no-store        (personalised)
Cache-Control: public, max-age=86400              (generic)

# locksmith — agent: my-first-agent
ACL-eligible tools (binding/source health checked at admission):
  - anthropic at /api/anthropic/...
  - openai    at /api/openai/...
  - tavily    at /api/tavily/...
...
```

The agentskills.io format. Useful for an LLM-based agent to bootstrap
its tool catalog at startup.

### `GET /tools` — kind=tool discovery

```
HTTP 200 application/json
Authorization: Bearer lk_...

{
  "tools": [
    {"name": "tavily", "type": "api", "path": "/api/tavily", "description": "Tavily search API"},
    {"name": "github", "type": "api", "path": "/api/github", "description": "GitHub REST API v3"}
  ]
}
```

Returns ONLY `kind=tool` registrations the calling agent's allowlist
permits. `kind=model` and `kind=infra` are filtered out (use `/models`
for models; infra is operator-only).

Active database entries also report `activation: active`, `account_selected`
and `credential_readiness: not_checked`. An optional validated `http_service`
describes methods, paths, query/body fields, response types, errors and examples.
Use the [versioned HTTP service contract](http-services.md) to construct calls;
its descriptions do not enforce method/path grants. Unrelated metadata stays
private. Legacy entries without a descriptor retain their existing behavior.

### `GET /models` — kind=model discovery

```
HTTP 200 application/json
Authorization: Bearer lk_...

{
  "models": [
    {"name": "anthropic", "type": "api", "path": "/api/anthropic", "description": "Anthropic Messages API"},
    {"name": "openai",    "type": "api", "path": "/api/openai",    "description": "OpenAI Responses + Chat Completions API"}
  ]
}
```

Same shape as `/tools`, but `kind=model` only. Both lists and personalized
`/skill` show ACL eligibility, not proof of explicit selection or source health.

### `ANY /api/{tool_name}/{*path}` — proxy hot path

The provider call. Locksmith:

1. Validates the bearer.
2. Checks the agent's ACL against `tool_name`.
3. Looks up the registration in the catalog.
4. Requires an explicit `(agent, registration)` binding, including `none`.
   Missing selection denies with 403 before dispatch; no registration default.
5. Resolves only the selected source; unavailable sources deny with 503.
   Strips agent-supplied auth and injects only that selected credential.
6. Forwards to the registration's `upstream + /{*path}`.
7. Streams the response back.
8. Audits.

#### Method + path passthrough

The HTTP method, request body, query string, and remaining path
segments after `tool_name` are forwarded as-is. So calling
`POST /api/anthropic/v1/messages` with a JSON body lands on
`POST <anthropic.upstream>/v1/messages` with the same body.

#### Headers

**Stripped from the agent's request** (defense-in-depth):

- `Authorization` (always — even when `auth: none`)
- `x-api-key` (always)
- `host`
- The target's own auth header (e.g., `x-api-key` for anthropic
  registrations, `Authorization` for bearer ones)

**Forwarded as-is**: any other header the agent sends (e.g.,
`anthropic-version`, `content-type`, custom application headers).

**Injected by locksmith**:

- For `AuthSpec::Header { header, env_var }`: `<header>: <env-var-value>`
- For `AuthSpec::Bearer { env_var }`: `Authorization: Bearer <env-var-value>`
- For OAuth: `Authorization: Bearer <access_token-from-explicitly-selected-session>`
- For `AuthSpec::None`: nothing.

The selected Header/Bearer source may reference environment, stored credentials
or 1Password. OAuth requires a nonempty session label and complete, consistent
provider metadata; bootstrap alone does not authorize use. The agent never sees
the injected credential. Identityless legacy calls cannot use credentialed
registration defaults; only explicitly authless registrations are supported.

#### Response headers

Locksmith returns the upstream's response headers, minus hop-by-hop ones.
A header the upstream sends more than once, such as `Set-Cookie` or `Link`,
arrives as every value it sent.

URLs in `Link` and `Location` that point under the route's upstream base
are rewritten to the same path under the route on Locksmith. The new base is
`<scheme>://<Host header>/api/<route>`, where the scheme is `https` on the
TLS listener and `http` otherwise. GitHub pagination therefore works as
usual: follow `rel="next"` and the next page goes through Locksmith with the
same credential. Only the link target itself is rewritten (the whole
`Location` value, or each `<...>` in `Link`), and only when it starts with
the configured upstream exactly, including case and port, and continues with
a path. URLs to other hosts, URLs inside another URL's query, and links to
the bare upstream base are left as they are. If the request has no `Host`
header, or it is not a plain host and port, nothing is rewritten.

Behind a TLS-terminating front end, the plain-HTTP listener sees `http`, so
rewritten links use `http://<public host>`. Make the front end redirect or
refuse plain HTTP, or agents following such a link would send their bearer
unencrypted.

Locksmith does not follow redirects. The agent receives the upstream's
3xx, with a `Location` on the route's own upstream rewritten as above, so
following it goes back through Locksmith with the same credential. A
redirect to another host (for example GitHub's tarball and log downloads,
which point at signed storage URLs) keeps its original `Location`; the
agent fetches it directly, without Locksmith's credential, over its own
egress. Use a client that follows redirects (`curl -L`, most HTTP
libraries by default) and drops `Authorization` on a host change, which
standard clients do.

#### Streaming

Locksmith streams the upstream response body chunk-by-chunk. SSE
streams (Anthropic, OpenAI completion streaming) work natively — no
buffering. R-N6 contract: ≤100ms first-byte added latency.

When response controls are configured (`max_size_bytes` /
`content_type_allowlist` / `redaction_patterns`), behavior depends
on the policy:

- `max_size_bytes` only → stream with size cap (truncates with
  marker if exceeded; see below).
- `redaction_patterns` → buffer the whole response, apply regex,
  then return.
- `content_type_allowlist` → stream-time pre-check.

## Error envelope

Every error locksmith generates on the proxy path renders as:

```json
{
  "error": {
    "type": "...",     // auth_error | authz_error | not_found | bad_request | payload_too_large | availability_error | upstream_error | timeout | response_size_exceeded | response_content_type_disallowed
    "code": "...",     // specific machine-readable code
    "message": "..."   // human-readable explanation
  }
}
```

An error status returned by the upstream itself (for example a provider's
429 or 500) passes through with the upstream's own body; it is not wrapped
in this envelope.

Codes:

| HTTP | type | code | When |
|---|---|---|---|
| 400 | `bad_request` | `bad_request` | Request body unreadable or larger than the registration's body limit. |
| 401 | `auth_error` | `invalid_credential` | Bearer missing, malformed or rejected (uniform wire code), or the agent is no longer active. |
| 401 | `auth_error` | `agent_identity_required` | Identityless request to a credentialed registration. |
| 403 | `authz_error` | `tool_not_allowed` | ACL denies, or no explicit account binding; audit distinguishes the cause. |
| 404 | `not_found` | `tool_not_found` | Allowlisted name that is not registered or not enabled. |
| 413 | `payload_too_large` | `codex_body_too_large` | Codex `/responses` request body over 1 MiB. |
| 502 | `upstream_error` | `upstream_error` | Upstream unreachable, the request to it failed, or its response body could not be read. |
| 502 | `response_content_type_disallowed` | `response_content_type_disallowed` | M7 content-type allowlist rejected the response. |
| 502 | `response_size_exceeded` | `response_size_exceeded` | M7 size cap exceeded on a buffered response (redaction configured). Streamed responses are truncated instead; see below. |
| 503 | `availability_error` | `connection_not_active` | Registration is not active in the running daemon (for example, persisted and runtime state differ). |
| 503 | `auth_error` | `credential_unresolved` | Selected source unavailable; no alternate/default dispatch. |
| 503 | `auth_error` | `oauth_session_missing` | OAuth tool but no session bootstrapped. |
| 503 | `auth_error` | `oauth_refresh_failed` | OAuth session degraded; operator action required. |
| 503 | `auth_error` | `oauth_sealing_key_unset` | OAuth tool but daemon has no sealing key. |
| 504 | `timeout` | `timeout` | Upstream took longer than configured timeout. |

For 403, the operator checks audit `details.reason`: `account_binding_missing`
requires `locksmith agent credentials list <agent-public-id>` then deliberate
`locksmith agent set-credential <agent-public-id> <tool> --auth 'bearer=<ENV_VAR>'`
(or an approved supported source). Only `not_in_allowlist` / `in_denylist`
justify reviewing ACL policy. For 503, inspect selected references/labels/status,
repair that source, and never retry with an alternate account/default/no auth.
See [binding troubleshooting](../operator/account-binding-troubleshooting.md).

**Existence-leak avoidance (Q-8)**: agent-facing errors don't reveal
whether a name exists in the catalog. Without a valid bearer every
`/api/{name}/...` request returns 401. With a valid bearer, a name outside
the agent's allowlist returns 403 `tool_not_allowed` whether or not it is
registered. 404 `tool_not_found` is returned only for a name the agent is
allowed that is not registered or not enabled.

## Streaming contract details

For Anthropic / OpenAI / streaming completion-style:

- Upstream response `Content-Type: text/event-stream` flows through
  unchanged.
- Heartbeat / keepalive frames are forwarded as-is.
- Stream truncation (size cap exceeded): locksmith forwards the bytes
  that fit under the cap, appends the literal marker
  `\n{"_locksmith":"response_size_exceeded"}\n`, and ends the stream.
  The status stays as sent (usually 200). The marker is not an SSE
  `data:` frame and no `[DONE]` frame follows, so a client should treat
  an unterminated stream that ends with this marker as truncated.

## Audit fields agents can correlate against

If your agent wants to correlate locksmith's audit rows back to its
own logs, the stable identifiers are:

- `agent_public_id` — your agent's stable public ID (the part before
  the `.` in your bearer).
- `tool` — the registration name in the URL.
- `path` — the suffix after `/api/{tool}/`.
- `oauth_session_id` (OAuth requests) — sha256-derived; stable across
  access-token refreshes within a session.

Locksmith does NOT pass through arbitrary correlation IDs — if you
need request-level correlation, your agent should set its own
identifying header (e.g., `x-request-id: ...`) which locksmith
forwards untouched.

## Worked example: Anthropic

```http
POST /api/anthropic/v1/messages HTTP/1.1
Host: layer8.lan:9200
Authorization: Bearer lk_yN2vR6jFKNYfIwNjFU2MSA.1TJlTmOgmswZYZx_aQHyjaNiugeJjudytNPFJgT9aqM
anthropic-version: 2023-06-01
Content-Type: application/json

{
  "model": "claude-haiku-4-5",
  "max_tokens": 100,
  "messages": [{"role": "user", "content": "Hello"}]
}
```

What locksmith forwards to Anthropic:

```http
POST /v1/messages HTTP/1.1
Host: api.anthropic.com
x-api-key: sk-ant-...                            ← injected from .env
anthropic-version: 2023-06-01                    ← passed through
Content-Type: application/json                   ← passed through

{ ... same body ... }
```

What flows back: Anthropic's response (status, headers, body),
streamed through locksmith with one audit row written.

## See also

- [`openclaw.md`](openclaw.md) — openclaw integration recipe.
- [`hermes.md`](hermes.md) — hermes integration recipe (planned).
- [`examples/`](examples/) — curl + Python + TypeScript snippets
  (planned).
- [`../concepts/error-envelope.md`](../concepts/error-envelope.md) —
  conceptual deep-dive on the envelope shape + Q-8.
- [`../concepts/agent-identity-and-acl.md`](../concepts/agent-identity-and-acl.md)
  — bearer token semantics + ACL evaluation.
