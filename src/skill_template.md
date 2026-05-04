---
name: locksmith
description: Credential proxy that mediates AI-agent calls to upstream LLMs and tools. Per-agent bearer authentication, per-agent ACL on tool routes, structured audit, uniform error envelope.
version: 2.0.0
format: agentskills.io
---

# Locksmith — agent skill

You're talking to **agent-locksmith**, a credential proxy that:

- Authenticates the calling agent (per-agent bearer token).
- Enforces a per-agent ACL on every tool call.
- Injects upstream provider credentials at the proxy layer (your code never sees them).
- Audits every request for the operator.

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
- The exact list of tools you may call (and short descriptions).
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
| `GET /tools` | per-agent bearer | JSON catalog of tools you may call (filtered by your ACL). |
| `ANY /api/<tool>/<upstream-path>` | per-agent bearer | Proxy to the upstream tool. Path after `<tool>` is forwarded verbatim. |
| `GET /livez`, `/readyz`, `/version`, `/health` | none | Health and version probes. |

## Wire envelope (errors)

All authentication and authorization failures use a uniform JSON shape:

```json
{
  "error": {
    "message": "<human-readable>",
    "type":    "auth_error" | "authz_error",
    "code":    "invalid_credential" | "expired" | "revoked" | "rate_limited" |
               "tool_not_allowed" | "internal_error" | "backend_error"
  }
}
```

Status codes:

- `401` — `type: auth_error`: token missing, malformed, unknown, expired, or
  revoked. The wire never distinguishes between these — see §4.7.9 / Q-8 for
  the existence-leak rationale. The audit row carries the discriminating
  reason.
- `403` — `type: authz_error code: tool_not_allowed`: token valid, but the
  requested tool isn't in your ACL.
- `429` — `type: auth_error code: rate_limited`: includes a `Retry-After`
  header (seconds).
- `500` — `type: auth_error code: internal_error | backend_error`: server-side
  issue. The wire message is generic; the operator's logs carry the
  discriminator.

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

Your operator can grant or revoke tool access via:

```
locksmith agent modify <your-public-id> --allowlist tool1,tool2 --denylist tool3
```

The personalized form of this skill (re-fetched with your bearer) lists
exactly which tools you can call right now.

## Format

This document follows the [agentskills.io](https://agentskills.io) skill
convention. Agents that natively load `agentskills.io` skills can ingest the
output of `GET /skill` directly as a system-prompt skill definition.
