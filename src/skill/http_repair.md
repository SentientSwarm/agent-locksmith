
## HTTP proxy error envelope

HTTP proxy authentication and authorization failures use a uniform JSON shape:

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

## HTTP authentication diagnosis

Ask your operator to grep the security audit for your `public_id` (or for
recent `auth_failure` rows). The operator-facing recipe:

```
locksmith audit query --event-class security --since-ms <ms>
```

The audit row's `details.reason` will say one of: `missing_credential`,
`malformed_token`, `wrong_namespace`, `unknown_public_id`, `secret_mismatch`,
or `expired`.

## HTTP 403 repair

Do not infer the cause from `tool_not_allowed` alone. Ask your operator to
inspect the security audit for your public ID. `details.reason` distinguishes:

- `account_binding_missing`: your ACL may already allow the tool. Diagnose
  the selection first, then deliberately choose the intended account:

  ```
  locksmith agent credentials list <agent-public-id>
  locksmith agent set-credential <agent-public-id> <tool> --auth 'bearer=<ENV_VAR>'
  ```

  The environment reference is an operator-chosen example, not a credential
  value. Other HTTP selections include stored credentials, 1Password
  references, explicit `--no-auth`, and `--oauth-session <label>`.
  Never paste secrets into chat or evidence. Clearing a binding denies the
  next admission; it does not restore a registration default.
- `not_in_allowlist` / `in_denylist`: ask the operator whether a policy change
  is intended. Only then use `locksmith agent modify <agent-public-id>
  --allowlist tool1,tool2 --denylist tool3` with the intended complete lists.
  Widening an ACL does not repair a missing binding.

## HTTP 503 repair

Ask the operator to run `locksmith agent credentials list <agent-public-id>`
and inspect safe source references, OAuth labels/status and proxy audit events:

```
locksmith audit query --event-class proxy --agent <agent-public-id> --since-ms <ms>
```

Use the incident start in Unix milliseconds for `<ms>`. A credential failure
uses `event=credential_unavailable` and `details.credential_cause`;
OAuth failures use `details.oauth_cause`; activation failures use `details.cause`.
A security-only audit filter does not include these proxy failures.
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
