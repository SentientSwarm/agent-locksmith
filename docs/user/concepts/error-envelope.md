# Error envelope

The uniform JSON shape locksmith returns for every authentication and authorization failure. User-level reference; authoritative version: `agents-stack/docs/spec/v<X.Y.Z>.md` §4.7.9 and `agents-stack/docs/adrs/0002-uniform-error-envelope.md`.

## The shape

```json
{
  "error": {
    "message": "<human-readable, intentionally generic>",
    "type":    "auth_error" | "authz_error",
    "code":    "<stable machine-readable discriminator>"
  }
}
```

Three fields, every error response, every time. The `code` field is the stable contract; `message` is for humans and may evolve; `type` distinguishes "you're not who you say" (auth_error) from "you are who you say but you can't do that" (authz_error).

## The type / code matrix

| HTTP | type | code | When |
|------|------|------|------|
| 401 | `auth_error` | `invalid_credential` | Bearer missing, malformed, unknown public_id, wrong-namespace, expired, revoked, secret-mismatch — any reason at all. The wire **does not** distinguish between these (see Q-8 below). |
| 401 | `auth_error` | `internal_error` | Internal failure during auth (DB unreachable, etc.). The audit log carries the discriminating cause. |
| 403 | `authz_error` | `tool_not_allowed` | Bearer is valid; the requested tool/model isn't in the agent's allowlist (or is in the denylist). |
| 403 | `authz_error` | `wrong_kind` | (v2.0.0+) Operation references a name registered under a different kind (e.g., `PUT /admin/models/anthropic` when anthropic is `kind=tool`). |
| 400 | `bad_request` | `reserved_name` | (v2.0.0+) Admin operation tried to register a name on the reserved list (`livez`, `readyz`, `version`, `health`, `skill`, `tools`, `models`, `admin`, `api`). |
| 400 | `bad_request` | `auth_required` | (v2.0.0+) Admin operation registered `kind=tool` without `auth:` — must state `auth: none` explicitly for authless tools. |
| 409 | `conflict` | `name_in_use` | (v2.0.0+) Cross-kind name reuse (e.g., a name already exists with a different kind). |
| 429 | `auth_error` | `rate_limited` | Token validation rate-limited. Includes `Retry-After` header (seconds). |
| 5xx | `auth_error` | `backend_error` | Backend persistence error during auth. The wire message is generic; the operator's logs carry the discriminator. |

## Q-8: existence-leak avoidance

You'll notice the table above collapses six different bearer-failure modes into a single 401 / `invalid_credential`. This is deliberate:

> **An attacker who can probe the wire must not be able to distinguish "this public_id doesn't exist" from "this public_id exists but the secret is wrong" from "this public_id was revoked".**

If we returned `code: unknown_public_id` vs `code: secret_mismatch`, an attacker scanning a range of public_ids could enumerate which ones exist on the system without ever guessing a secret. We don't.

The audit log's `details.reason` field carries the exact discriminator — `missing_credential`, `malformed_token`, `wrong_namespace`, `unknown_public_id`, `secret_mismatch`, `expired` — for the **operator** to investigate. The wire stays uniform.

## Examples

### Missing bearer

```http
GET /api/anthropic/v1/messages
```

```http
HTTP/1.1 401 Unauthorized
Content-Type: application/json

{"error": {"message": "invalid credential", "type": "auth_error", "code": "invalid_credential"}}
```

### Valid bearer, denied tool

```http
GET /api/anthropic/v1/messages
Authorization: Bearer lk_<valid-but-narrow-agent>.xxx
```

```http
HTTP/1.1 403 Forbidden
Content-Type: application/json

{"error": {"message": "tool not allowed for this agent", "type": "authz_error", "code": "tool_not_allowed"}}
```

### Rate-limited

```http
HTTP/1.1 429 Too Many Requests
Retry-After: 30
Content-Type: application/json

{"error": {"message": "rate limited", "type": "auth_error", "code": "rate_limited"}}
```

## Agent-developer practical guidance

- **Read `code`, not `message`.** Codes are the stable contract; messages may evolve.
- **Don't try to parse 401 sub-reasons from the wire.** They aren't there. If you persistently 401, ask the operator to grep the audit log for your `public_id`.
- **403 `tool_not_allowed` is permanent for the current bearer.** Don't retry; don't downgrade. Either request a broader ACL or change which tool you're calling.
- **429 `rate_limited` honors `Retry-After`.** Back off for the indicated seconds.
- **5xx is "the proxy itself is in trouble".** Bubble up; don't loop.

## Operator practical guidance

For 401 troubleshooting, the audit log is the discriminator:

```bash
locksmith audit query --event-class security --agent-public-id <pid> --limit 20
```

Look at `details.reason`:

| reason | What it means | Likely fix |
|--------|---------------|------------|
| `missing_credential` | No `Authorization` header on the request | Agent code didn't send it |
| `malformed_token` | Header present but didn't parse as `Bearer lk_<pid>.<secret>` | Agent corrupted/truncated the token |
| `wrong_namespace` | Token started with something other than `lk_` | Agent used a token from a different system |
| `unknown_public_id` | `public_id` not in the agents table | Agent was revoked or never registered on this host |
| `secret_mismatch` | `public_id` known, secret hash didn't match | Old token after rotation; or the agent was issued a token for a different deployment |
| `expired` | Token TTL elapsed (when expirations are configured) | Re-register and redistribute |

Same code on the wire (`invalid_credential`); different reason in the log; different fix.

## See also

- [trust-boundary.md](trust-boundary.md)
- [agent-identity-and-acl.md](agent-identity-and-acl.md)
- `agents-stack/docs/adrs/0002-uniform-error-envelope.md` — formal decision record.
- `agents-stack/docs/adrs/0003-existence-leak-q8.md` — formal Q-8 rationale.
