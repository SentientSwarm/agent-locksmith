# Agent identity and ACL

How locksmith authenticates an agent on every request and decides what tools it may call. User-level explanation; authoritative version: `agents-stack/docs/spec/v<X.Y.Z>.md`.

## What is an agent identity

When the operator runs `locksmith agent register`, the daemon creates a row in the agents table with:

- **`name`** — human-readable label (`hermes-mini-m1`, `research-bot`, `verify-test`). Operator-chosen, must be unique.
- **`public_id`** — opaque identifier, appears in bearer tokens and audit rows. Daemon-generated.
- **`allowlist`** — list of tool/model names the agent may call.
- **`denylist`** — list of tool/model names the agent must not call (deny wins).
- **`secret_hash`** — argon2 hash of the bearer secret (cleartext returned exactly once at register time).
- **(optional)** `cert_identity` — for mTLS-authenticated agents (v0.2 feature flag), the SAN to match.

The bearer token issued to the agent encodes the `public_id`; the daemon resolves it back to the full `AgentIdentity` on every request.

## What ACL means

ACL is **flat**: an agent has a single allowlist + denylist that applies uniformly across all kinds of registration (tool, model, infra). Pre-Phase E the only kind is `tool`; from v2.0.0 the agent doesn't need to know whether `anthropic` is a model or a tool — it just has `anthropic` in its allowlist.

**Resolution order on every request:**

1. **Authenticate the bearer** → `AgentIdentity` or 401.
2. **Extract the requested registration name** from the URL: `/api/<name>/...`.
3. **Apply denylist** — if name is in denylist → 403 `tool_not_allowed`.
4. **Apply allowlist** — if an allowlist is set and name isn't in it → 403 `tool_not_allowed`.
5. **Absent allowlist** = unrestricted by allowlist; an explicitly empty list permits no names. Denylist still wins.
6. **Require explicit account selection** for the authenticated registration, including deliberate `none`. Missing binding → 403; selected source unavailable → 503; neither dispatches upstream or inherits the registration template.

ACL decisions are emitted as `EventClass::Security` audit rows with the `agent_public_id` so security review can grep for "what did agent X try to call?" or "who tried to call denied tool Y?".

## Discovery endpoints

Agents can ask locksmith which registrations are eligible under their ACL:

- `GET /tools` — JSON catalog of allowed tools (filtered by ACL). At v2.0.0 this returns only `kind=tool` entries.
- `GET /models` — (v2.0.0+) JSON catalog of allowed models, filtered by ACL.
- `GET /skill` — agentskills.io-format markdown describing locksmith. Without a bearer it returns a generic form (no tool/model leakage); with a valid bearer it returns a personalized form listing the agent's ACL-eligible catalog entries.

Discovery respects ACL eligibility; it does not check binding existence or selected source health. A listed entry may still return 403 for missing selection or 503 for an unavailable selected source.

## What goes in the audit log

Every authenticated request emits an audit row with:

- `agent_public_id` — who sent it
- `registration_name` — what they asked for
- `decision` — allow / deny + reason code
- `auth_method` — bearer / mtls
- timestamp, request id, etc.

For 403 denials, `details.reason` distinguishes `not_in_allowlist`,
`in_denylist` and `account_binding_missing` (same wire code `tool_not_allowed`).
Use `locksmith audit query --event-class security --agent <agent-public-id>`.
For missing selection, first run `locksmith agent credentials list <agent-public-id>`,
then deliberately select the intended account with
`locksmith agent set-credential <agent-public-id> <tool> --auth 'bearer=<ENV_VAR>'`
or another approved supported source. Only actual ACL reasons justify reviewing
policy. Do not print credential values or retry an alternate account/default/no auth.

Each agent has its own identity and explicit selection. Several agents can
intentionally select the same source/account, preserving per-agent audit
attribution; distinct bindings can instead isolate billing/quota and identity.
See [per-agent credentials](per-agent-credentials.md). Registration defaults
never supply implicit account authority.

## Operator practical guidance

- **Start narrow.** New agents register with the smallest viable allowlist. Add as you discover real needs. Denylist is rarely needed if allowlists are tight.
- **Give each agent its own identity.** Don't reuse a bearer across agents — you lose the audit attribution. The bearer secret is cheap to mint.
- **Rotate when in doubt.** `locksmith agent revoke <agent-public-id>` invalidates the bearer immediately; re-register with `--allowlist ...` to mint a new one.
- **For verify-test agents:** keep them in `agents.test.yaml` (separate manifest) with deliberately-narrow allowlists so verify.sh can prove both allow and deny paths concretely. See `layer8-proxy-site/agents.test.yaml` for the convention.

## Agent-developer practical guidance

- **Send `Authorization: Bearer lk_<public_id>.<secret>` on every request.** No exceptions; no fallback to "no auth header for some endpoints" except the public probes (`/livez`, `/readyz`, `/version`, unauthenticated `/skill`).
- **Use `GET /skill` (with your bearer) on startup** to discover what's available. Don't hardcode a list locally — it goes stale.
- **On 403, read the stable code and ask the operator to inspect the audit reason.** `tool_not_allowed` alone cannot distinguish missing binding from ACL denial. On 503, ask for selected-source diagnosis; discovery is not proof of source health.
- **On 401, stop and ask the operator.** Re-trying the same request with the same bearer won't succeed. Ask for a fresh bearer or a registration sanity-check.

## See also

- [trust-boundary.md](trust-boundary.md) — what the bearer protects.
- [error-envelope.md](error-envelope.md) — exact 401 / 403 wire shapes.
- [../agent-integration/wire-contract.md](../agent-integration/wire-contract.md) — full HTTP contract for agents.
- [../agent-integration/skill-reference.md](../agent-integration/skill-reference.md) — `/skill` endpoint detail.
