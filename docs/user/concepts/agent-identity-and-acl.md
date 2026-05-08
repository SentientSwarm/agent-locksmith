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
4. **Apply allowlist** — if allowlist is non-empty and name isn't in it → 403 `tool_not_allowed`.
5. **Empty allowlist + empty denylist** = no agent-side restriction (operator-implicit deny via "we just don't tell the agent it exists" works too).

ACL decisions are emitted as `EventClass::Security` audit rows with the `agent_public_id` so security review can grep for "what did agent X try to call?" or "who tried to call denied tool Y?".

## Discovery endpoints

Agents can ask locksmith what they're allowed to use:

- `GET /tools` — JSON catalog of allowed tools (filtered by ACL). At v2.0.0 this returns only `kind=tool` entries.
- `GET /models` — (v2.0.0+) JSON catalog of allowed models, filtered by ACL.
- `GET /skill` — agentskills.io-format markdown describing locksmith. Without a bearer it returns a generic form (no tool/model leakage); with a valid bearer it returns a personalized form listing the agent's exact allowlist.

The discovery endpoints respect the same ACL the proxy hot path uses, so an agent never sees an entry it can't actually call.

## What goes in the audit log

Every authenticated request emits an audit row with:

- `agent_public_id` — who sent it
- `registration_name` — what they asked for
- `decision` — allow / deny + reason code
- `auth_method` — bearer / mtls
- timestamp, request id, etc.

For ACL denials specifically, the audit row's `details.reason` is one of:
- `tool_not_allowed` — name not in allowlist (or in denylist)
- `tool_unknown` — name doesn't exist in the registry

Use `locksmith audit query --event-class security --agent-public-id <pid>` to investigate.

> **"Who made this call?" is already answered today.** Every
> `proxy_request` audit row carries `agent_public_id` and (post-G.0)
> `agent_name`. If your only concern about shared upstream
> credentials is per-agent attribution, you don't need per-agent
> credentials — the audit log already partitions calls by agent.
> Reach for [per-agent credentials](per-agent-credentials.md) only
> when you need upstream-side billing/quota separation, blast-radius
> isolation, or distinct upstream identities. For most teams the
> shared-credential default is the right answer.

## Operator practical guidance

- **Start narrow.** New agents register with the smallest viable allowlist. Add as you discover real needs. Denylist is rarely needed if allowlists are tight.
- **Give each agent its own identity.** Don't reuse a bearer across agents — you lose the audit attribution. The bearer secret is cheap to mint.
- **Rotate when in doubt.** `locksmith agent revoke <name>` invalidates the bearer immediately; re-register with `--allowlist ...` to mint a new one.
- **For verify-test agents:** keep them in `agents.test.yaml` (separate manifest) with deliberately-narrow allowlists so verify.sh can prove both allow and deny paths concretely. See `layer8-proxy-site/agents.test.yaml` for the convention.

## Agent-developer practical guidance

- **Send `Authorization: Bearer lk_<public_id>.<secret>` on every request.** No exceptions; no fallback to "no auth header for some endpoints" except the public probes (`/livez`, `/readyz`, `/version`, unauthenticated `/skill`).
- **Use `GET /skill` (with your bearer) on startup** to discover what's available. Don't hardcode a list locally — it goes stale.
- **On 403, look at the `code` field, not the `message`.** The wire intentionally returns generic messages; codes are stable contract.
- **On 401, stop and ask the operator.** Re-trying the same request with the same bearer won't succeed. Ask for a fresh bearer or a registration sanity-check.

## See also

- [trust-boundary.md](trust-boundary.md) — what the bearer protects.
- [error-envelope.md](error-envelope.md) — exact 401 / 403 wire shapes.
- [../agent-integration/wire-contract.md](../agent-integration/wire-contract.md) — full HTTP contract for agents.
- [../agent-integration/skill-reference.md](../agent-integration/skill-reference.md) — `/skill` endpoint detail.
