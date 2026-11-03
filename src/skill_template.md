---
name: locksmith
description: Credential proxy that mediates AI-agent calls to upstream LLMs and tools. Per-agent bearer authentication, per-agent ACL on tool routes, structured audit, uniform error envelope, fully-transparent codex integration (Phase G2/G3/G4).
version: 2.4.0
format: agentskills.io
---

# Locksmith — agent skill

You're talking to **agent-locksmith**, a credential proxy that:

- Authenticates the calling agent (per-agent bearer token).
- Enforces a reviewed finite per-agent grant on every HTTP connection call.
  Missing/null/empty grants permit nothing; new connections require explicit approval.
  Grants cover the entire connection. Narrow method/resource/operation selectors are unsupported.
- Requires an explicit account binding for every authenticated proxy call,
  including a deliberate `none` binding for an authless registration.
- Injects only the selected upstream provider credentials at the proxy layer (your code never sees them).
- Audits every request for the operator.
- For codex (OpenAI ChatGPT plan auth), transparently injects the
  `ChatGPT-Account-ID` header (Phase G2), the required body fields
  `store: false`, `stream: true`, default `instructions` (Phase G3),
  and the required `OpenAI-Beta` + `originator` headers (Phase G4)
  — see the codex section below. Agents call codex with only
  `Authorization` + minimal body.

## Authentication

Every authenticated request must carry:

```
Authorization: Bearer lk_<public_id>.<secret>
```

Tokens are issued by your operator via `locksmith agent register`. Acquire yours
out-of-band (operator distribution; this endpoint never returns one).

## Personalized skill

This document is the **generic** form. Re-fetch with your bearer to receive the
**personalized** form, which adds:

- Your agent name and `public_id`.
- Your ACL-eligible tools (and short descriptions).
- Per-tool integration guidance (codex specifics if codex is in your ACL).
- An audit-debug recipe scoped to your `public_id` so your operator can
  trace any 401 / 403 you receive.

```
curl -fsS -H "Authorization: Bearer $LOCKSMITH_TOKEN" http://<locksmith>/skill
```

The personalized form requires the same bearer that authorizes `/api/...`
calls. There is no separate auth scheme for this endpoint.

## Endpoints

| Path | Auth | Purpose |
|------|------|---------|
| `GET /skill` | optional | This document. With no `Authorization` header, returns this generic form. With a valid `Authorization: Bearer lk_…`, returns the personalized form (your tools, your ACL, audit-debug recipes). With an invalid bearer, returns 401 — no silent downgrade. |
| `GET /tools` | per-agent bearer | JSON catalog of tools eligible under your ACL. |
| `GET /models` | per-agent bearer | JSON catalog of LLM-kind tools (`kind=model`) eligible under your ACL. |
| `ANY /api/<tool>/<upstream-path>` | per-agent bearer | Proxy to the upstream tool. Path after `<tool>` is forwarded verbatim. |
| `GET /livez`, `/readyz`, `/version`, `/health` | none | Health and version probes. |

## What locksmith does for you vs what you do

| Layer | Locksmith handles | You handle |
|---|---|---|
| Auth (locksmith ↔ agent) | Validates your bearer; enforces ACL; emits audit row per request. | Send `Authorization: Bearer lk_…` on every request. |
| Auth (locksmith ↔ upstream) | Strips your `Authorization` / `x-api-key` headers; injects the explicitly selected upstream credential (API key, OAuth access token, etc.). Refresh-ahead-of-expiry for OAuth providers. | Nothing. You never see the upstream credential. |
| Wire framing | Recomputes `Content-Length` based on the body locksmith forwards. Strips `Transfer-Encoding` for the same reason. | Don't rely on your `Content-Length` reaching upstream — set the body, trust locksmith to frame it. |
| Path routing | Strips `/api/<tool>` prefix; forwards the remainder to the configured upstream URL. | Construct request as `POST /api/<tool>/<upstream-path>` per the wire-shape of the upstream. |
| Codex `ChatGPT-Account-ID` header | Extracts from JWT at OAuth bootstrap; injects on `/backend-api/codex/*` requests automatically (Phase G2). | Don't send it yourself — locksmith owns this. |
| Codex body fields `store` / `stream` / `instructions` | On `/responses` paths: forces `store: false`, `stream: true`, injects default `instructions` if missing (Phase G3). | Send the rest of the body shape as the upstream expects. Override `instructions` if you want a non-default system prompt — locksmith preserves user-supplied values. |
| Codex required headers `OpenAI-Beta` / `originator` | Forces `OpenAI-Beta: responses=experimental`; injects `originator: <agent-name>` if missing, preserves yours otherwise (Phase G4). | Optionally set your own `originator` if you want a non-default identifier on codex's side; otherwise nothing to do. |

## Per-tool wire shape

Each tool you can call has its own upstream-specific wire shape. Common
patterns:

- **OpenAI-compatible chat/completions** (lmstudio, ollama, openai, openrouter,
  ai-gateway): `POST /api/<tool>/v1/chat/completions` with the standard
  OpenAI request body (`model`, `messages`, `stream`, etc.).
- **Anthropic Messages API** (anthropic, anthropic-oauth): `POST /api/anthropic/v1/messages`
  with the Anthropic body shape (`model`, `messages`, `max_tokens`, `system`).
- **OpenAI Responses API** (codex): `POST /api/codex/responses` — see the
  dedicated codex section below; locksmith handles the upstream-specific
  quirks but you must send specific headers.
- **REST API tools** (tavily, github, duckduckgo, wikipedia): standard REST
  paths under `/api/<tool>/<rest-of-path>`. Method + body shape per the
  upstream's own docs.

The personalized `/skill` (re-fetched with your bearer) lists the tools
eligible under your ACL. These listings show **ACL eligibility**, not selected source health.
Database listings require current runtime activation; JSON also reports
`account_selected` and `credential_readiness: not_checked`. A listed tool may
still return 403 for no selection or 503 for an unavailable selected source.
Config-only legacy listings say `configuration_only`. `/readyz` does not attest
every per-agent source. On `connection_not_active`, ask the operator to inspect
the saved connection and restore runtime activation. A saved admin write may
return `connection_activation_failed`; it is not rolled back. Never retry another
account or widen a grant automatically.

## Codex (OpenAI ChatGPT plan auth) — special case

OpenAI's `/backend-api/codex/responses` endpoint has stricter
requirements than the generic OpenAI-compat shape. **As of v2.5.2,
locksmith handles all of them transparently** — agents call codex
the same way they'd call any other OpenAI-compatible endpoint.

### What locksmith does

- **`Authorization` header**: injects the OAuth access token
  (refreshed ahead of expiry; you never see the JWT).
- **`ChatGPT-Account-ID` header (Phase G2)**: extracted from the
  access-token JWT at bootstrap, injected on every
  `/backend-api/codex/*` request.
- **`OpenAI-Beta` header (Phase G4)**: forced to
  `responses=experimental` on every codex request. Your supplied
  value (if any) is stripped — codex requires this exact value.
- **`originator` header (Phase G4)**: injected with your agent name
  if you didn't supply one. Preserves yours if you did.
- **Body field `store`**: forced to `false` (codex rejects `true`).
- **Body field `stream`**: forced to `true` (codex rejects `false`).
- **Body field `instructions`**: injected with default
  `"You are a helpful assistant."` if missing. **Preserved verbatim
  if you set it** — supply your own when you want a non-default
  system prompt.

### What you do

- **Send the request body in the OpenAI Responses API shape**:
  ```json
  {
    "model": "gpt-5.5",
    "input": [
      {
        "type": "message",
        "role": "user",
        "content": [
          { "type": "input_text", "text": "your prompt here" }
        ]
      }
    ]
  }
  ```
  (`store`, `stream`, `instructions` will be added/forced by locksmith.)
- **Handle the streaming response** — codex's `/responses` is
  fundamentally streaming (SSE). The `stream: true` is non-negotiable;
  agents that can't handle SSE will see a long response payload they
  can't process incrementally.

That's it. The minimal call is `POST /api/codex/responses` with
`Authorization: Bearer lk_…`, `Content-Type: application/json`, and
the body above. Everything else is locksmith.

### Codex body cap

Locksmith inspects codex `/responses` request bodies for body fixup.
Bodies > 1 MiB return **413 Payload Too Large** with envelope:

```json
{ "error": { "type": "payload_too_large", "code": "codex_body_too_large" } }
```

Codex bodies are tiny in practice (a few KB). The cap is a defense
against pathological streaming-body edge cases.

## Wire envelope (errors)

All authentication and authorization failures use a uniform JSON shape:

```json
{
  "error": {
    "message": "<human-readable>",
    "type":    "auth_error" | "authz_error" | "client_error" | "payload_too_large",
    "code":    "invalid_credential" | "expired" | "revoked" | "rate_limited" |
               "tool_not_allowed" | "internal_error" | "backend_error" |
               "credential_unresolved" | "agent_identity_required" |
               "oauth_session_missing" | "oauth_refresh_failed" |
               "oauth_sealing_key_unset" | "codex_body_too_large"
  }
}
```

Status codes:

- `401` — `type: auth_error`: token missing, malformed, unknown, expired, or
  revoked. The wire never distinguishes between these — see §4.7.9 / Q-8 for
  the existence-leak rationale. Identityless legacy credentialed routes return
  `agent_identity_required`. The audit row carries the discriminating
  reason.
- `403` — `type: authz_error code: tool_not_allowed`: token valid, but the
  requested tool is excluded by your ACL or has no explicit account binding.
- `413` — `type: payload_too_large code: codex_body_too_large`: codex
  request body exceeds the 1 MiB cap.
- `429` — `type: auth_error code: rate_limited`: includes a `Retry-After`
  header (seconds).
- `500` — `type: auth_error code: internal_error | backend_error`: server-side
  issue. The wire message is generic; the operator's logs carry the
  discriminator.
- `503` — `type: auth_error code: credential_unresolved | oauth_*`:
  the selected source is unavailable or OAuth is degraded. No upstream call
  is made; operator diagnosis is required.

## What to do if you get persistent 401s

Ask your operator to grep the security audit for your `public_id` (or for
recent `auth_failure` rows). The operator-facing recipe:

```
locksmith audit query --event-class security --since-ms <ms>
```

The audit row's `details.reason` will say one of: `missing_credential`,
`malformed_token`, `wrong_namespace`, `unknown_public_id`, `secret_mismatch`,
or `expired`.

## What to do if you get a 403

Do not infer the cause from `tool_not_allowed` alone. Ask your operator to
inspect the security audit for your public ID. `details.reason` distinguishes:

- `account_binding_missing`: your ACL may already allow the tool. Diagnose
  the selection first, then deliberately choose the intended account:

  ```
  locksmith agent credentials list <agent-public-id>
  locksmith agent set-credential <agent-public-id> <tool> --auth 'bearer=<ENV_VAR>'
  ```

  The environment reference is an operator-chosen example, not a credential
  value. Other supported selections include stored credentials, 1Password
  references, explicit `--no-auth`, and `--oauth-session <label>`.
  Never paste secrets into chat or evidence. Clearing a binding denies the
  next admission; it does not restore a registration default.
- `not_in_allowlist` / `in_denylist`: ask the operator whether a policy change
  is intended. Only then use `locksmith agent modify <agent-public-id>
  --allowlist tool1,tool2 --denylist tool3` with the intended complete lists.
  Widening an ACL does not repair a missing binding.

## What to do if you get a 503

Ask the operator to run `locksmith agent credentials list <agent-public-id>`
and inspect safe source references, OAuth labels/status and audit reasons.
The selected environment variable may be absent/empty, a stored credential
missing, a 1Password reference unresolved, or the selected OAuth session
missing, inconsistent, unsealable or unable to refresh. Repair that selected
source, or deliberately select a different approved account. Do not echo
credential values. A healthy registration default or another account is not
an alternate source for this request.

For OAuth, `locksmith oauth status <tool> --label <label>` inspects the selected
session. Bootstrap repairs session custody, not permission to use it: an
operator must separately select a nonempty label with
`locksmith agent set-credential <agent-public-id> <tool> --oauth-session <label>`.
Even the literal label `default` must be explicitly selected. See the operator
OAuth guide for the registration's required provider metadata and bootstrap's
private token input.

Never retry with another account, a registration default, or no authentication.
Avoid tight retries; wait for the operator to confirm the selected source is usable.

## Format

This document follows the [agentskills.io](https://agentskills.io) skill
convention. Agents that natively load `agentskills.io` skills can ingest the
output of `GET /skill` directly as a system-prompt skill definition.
