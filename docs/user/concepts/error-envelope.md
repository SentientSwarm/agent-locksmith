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
| 403 | `authz_error` | `tool_not_allowed` | Valid identity, but ACL denies or the explicit account binding is missing; inspect the operator audit reason. |
| 409 | `conflict` | `wrong_kind` | (v2.0.0+) Operation references a name registered under a different kind (e.g., `PUT /admin/models/anthropic` when anthropic is `kind=tool`). |
| 400 | `bad_request` | `reserved_name` | (v2.0.0+) Admin operation tried to register a name on the reserved list (`livez`, `readyz`, `version`, `health`, `skill`, `tools`, `models`, `admin`, `api`). |
| 400 | `bad_request` | `auth_required` | (v2.0.0+) Admin operation registered `kind=tool` without `auth:` — must state `auth: none` explicitly for authless tools. |
| 400 | `bad_request` | `invalid_upstream` | Operator tool/model destination is not an absolute HTTP(S) base URL, or contains userinfo, query or fragment. Validation does not echo the URL; no row, grant or selection changes. See [operator onboarding](../operator/connector-onboarding.md). |
| 400 | `bad_request` | `invalid_http_service` | Optional service metadata fails the strict versioned [HTTP descriptor contract](../agent-integration/http-services.md). Static error does not echo authored content; no row, grant or selection changes. |
| 409 | `conflict` | `name_in_use` | (v2.0.0+) Cross-kind name reuse (e.g., a name already exists with a different kind). |
| 503 | `auth_error` | `credential_unresolved` | Selected environment/stored/1Password source unavailable or selection unreadable. No alternate/default dispatch. |
| 503 | `auth_error` | `oauth_session_missing` / `oauth_refresh_failed` / `oauth_sealing_key_unset` | Selected OAuth session unavailable; operator diagnosis required. |
| 401 | `auth_error` | `agent_identity_required` | Identityless legacy request to a credentialed registration. |
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
- **403 `tool_not_allowed` needs operator diagnosis.** Audit `account_binding_missing` means select the intended account; `not_in_allowlist` / `in_denylist` mean review intended ACL policy. A deliberate repair can work with the same bearer. Never broaden ACLs as a universal repair or downgrade authentication.
- **429 `rate_limited` honors `Retry-After`.** Back off for the indicated seconds.
- **503 requires selected-source diagnosis.** Ask the operator to inspect safe references/labels/status and repair the selected source. Never retry an alternate account, registration default or unauthenticated call. Other 5xx errors should also be surfaced without tight loops.

## Operator practical guidance

For 401 troubleshooting, the audit log is the discriminator:

```bash
locksmith audit query --event-class security --agent <pid> --limit 20
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

For `tool_not_allowed`, distinguish policy from missing selection:

| Audit reason | Operator action |
| --- | --- |
| `account_binding_missing` | Run `locksmith agent credentials list <agent-public-id>`; deliberately select an approved source with `locksmith agent set-credential <agent-public-id> <tool> --auth 'bearer=<ENV_VAR>'` or another supported source. |
| `not_in_allowlist` / `in_denylist` | Review whether an ACL change is intended; account selection does not override policy. |

For 503, diagnose the selected environment reference, stored credential,
1Password cache reference or OAuth session before repair. Reads and reports
must contain references/status only, never credential values. Clearing a
binding denies the next admission. Catalog discovery proves ACL eligibility,
not binding existence or source health. See
[binding troubleshooting](../operator/account-binding-troubleshooting.md).

## See also

- [trust-boundary.md](trust-boundary.md)
- [agent-identity-and-acl.md](agent-identity-and-acl.md)
- `agents-stack/docs/adrs/0002-uniform-error-envelope.md` — formal decision record.
- `agents-stack/docs/adrs/0003-existence-leak-q8.md` — formal Q-8 rationale.
