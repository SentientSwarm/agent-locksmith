# Per-agent credentials

How to give two agents distinct upstream identities (separate API
keys, separate ChatGPT subscriptions) without proliferating
registrations. Phase G feature, paired with OAuth session labels.

## Default mode: shared credential + audit attribution

The default deployment shape is: **one credential per registration,
audit attribution per agent.** Every `proxy_request` audit row
already includes `agent_public_id` (and, post-G.0, `agent_name`),
so the question "who made this call?" is answered today even when
both agents share one upstream API key. For most teams this is the
right answer — it's simpler, cheaper, and audit-correct.

You only need per-agent credentials when one of these matters:

- **Upstream-side billing or quota separation.** Provider dashboards
  attribute by API key. Two agents on one OpenAI key are
  indistinguishable on the OpenAI side; per-agent keys give
  per-agent dashboards.
- **Blast radius isolation.** Revoking one agent's leaked key
  without touching the other agent.
- **Distinct upstream identities.** Each agent should run under its
  own ChatGPT account / GitHub account / etc.

If none of those bite, stop reading — shared credential is fine.

## What an override is

A row in `agent_credential_overrides` keyed on `(agent_id,
registration)`. When present, the proxy hot path replaces the
registration's default `auth_spec` with the override's BEFORE
credential injection.

```
agent             registration       override                              effective
─────────────────────────────────────────────────────────────────────────────────────
hermes-mini-1     lmstudio           bearer=LM_STUDIO_API_KEY_HERMES        LM_STUDIO_API_KEY_HERMES
openclaw-mini-1   lmstudio           (none)                                 LM_STUDIO_API_KEY (registration default)
hermes-mini-1     codex              oauth_session=hermes                   oauth_sessions(codex, "hermes")
openclaw-mini-1   codex              oauth_session=openclaw                 oauth_sessions(codex, "openclaw")
```

Default agents — those with no override row — see today's behavior
unchanged.

## Setting an override

```bash
# Static credential — different env var for hermes vs openclaw.
locksmith agent set-credential hermes-mini-1   lmstudio --auth bearer=LM_STUDIO_API_KEY_HERMES
locksmith agent set-credential openclaw-mini-1 lmstudio --auth bearer=LM_STUDIO_API_KEY_OPENCLAW

# Header injection (for `auth.kind = header` registrations).
locksmith agent set-credential hermes-mini-1 anthropic --auth header=x-api-key:ANTHROPIC_KEY_HERMES

# OAuth — pin to a specific session label (see below).
locksmith agent set-credential hermes-mini-1 codex --oauth-session hermes

# Downgrade to no-auth for a specific agent.
locksmith agent set-credential debug-bot lmstudio --no-auth

# Remove the override (agent goes back to registration default).
locksmith agent unset-credential hermes-mini-1 lmstudio

# See all overrides for one agent.
locksmith agent credentials list hermes-mini-1
```

The env var must exist in the daemon's environment at request time;
overrides read it on the hot path, not at startup. A missing env
var logs a warning and forwards the request without injection
(the upstream typically returns 401, surfaced in audit).

## OAuth labels

OAuth sessions live in the `oauth_sessions` table keyed on
`(registration_name, session_label)`. The default label is
`"default"`. Phase G adds the dimension; pre-Phase-G deployments
that never use `--label` see no change.

Per-agent OAuth uses two pieces:

1. **A distinct session per agent.** Each agent's owner completes
   the upstream OAuth flow under their own provider account, then
   the operator bootstraps it under a label:
   ```bash
   locksmith oauth bootstrap codex --label hermes   --refresh-token-stdin < hermes-rt.txt
   locksmith oauth bootstrap codex --label openclaw --refresh-token-stdin < openclaw-rt.txt
   ```

2. **A per-agent override pointing at the label.**
   ```bash
   locksmith agent set-credential hermes-mini-1   codex --oauth-session hermes
   locksmith agent set-credential openclaw-mini-1 codex --oauth-session openclaw
   ```

Now `hermes-mini-1`'s requests resolve `oauth_sessions(codex,
"hermes")` and `openclaw-mini-1`'s resolve
`oauth_sessions(codex, "openclaw")`.

## The OAuth single-grant trap

**One ChatGPT account cannot back two locksmith labels.** Most
identity providers — including OpenAI ChatGPT, GitHub, Google —
enforce a single-active-grant policy per (user, client_id). Logging
in a second time as the same user invalidates the prior refresh
token. So if you bootstrap two labels from the same upstream
account, only the most-recently-bootstrapped one will survive past
the next refresh cycle (~30 minutes for short-lived access tokens).

**`oauth bootstrap` warns at the time of the trap.** When a
non-default label is bootstrapped and other labels exist under the
same registration, the response carries a `warnings` field:

```json
{
  "name": "codex",
  "session_label": "hermes",
  "warnings": [
    "Registration `codex` already has session label(s): default. \
     If those sessions point at the same upstream account as label \
     `hermes`, the provider has likely invalidated the prior \
     refresh tokens (single-grant OAuth policy on OpenAI ChatGPT, \
     GitHub, Google, etc.). Per-agent OAuth requires distinct \
     upstream accounts; see concepts/per-agent-credentials.md."
  ]
}
```

The warning is advisory — bootstrap still succeeds. Operators
deliberately running two upstream accounts (one for hermes, one for
openclaw) can ignore it. Operators who didn't realize the trap exists
get a chance to step back before the prior session goes degraded.

## Audit attribution

Every `proxy_request` audit row carries:

- `agent_public_id` + `agent_name` — who made the call (G.0).
- `auth_source` — `"registration_default"` or `"agent_override"`.
- `auth_mode` — `"bearer"` / `"header"` / `"none"` /
  `"oauth_pkce"` / `"oauth_device_code"` / `"config"`.
- `oauth_session_id` — present on OAuth requests; SHA-256-based
  identifier stable per `(registration, label, created_at)`.
- `oauth_session_label` — the label resolved for the request
  (Phase G).

Grep recipes:

```bash
# All calls hermes made through an override:
locksmith audit query \
    --agent <hermes-public-id> \
    --decision allowed \
    --since-ms $(($(date +%s) * 1000 - 86400000)) \
    --format json \
    | jq '.[] | select(.details.auth_source == "agent_override") | {tool, ts: .ts_ms}'

# Confirm openclaw is using the openclaw OAuth session and not bleeding
# into hermes':
locksmith audit query --tool codex --since-ms ... --format json \
    | jq '.[] | {agent: .agent_name, label: .details.oauth_session_label}'
```

## Roll-out checklist

For a deployment moving from shared to per-agent credentials:

1. Generate the new upstream credentials. (For OAuth: each agent
   owner runs the provider's auth flow under their own account.)
2. Add env vars to the proxy host's `.env` (header/bearer overrides)
   or bootstrap OAuth sessions with `--label`.
3. Set per-agent overrides via `locksmith agent set-credential`.
4. Smoke-test by hitting a benign endpoint and grepping the audit
   row for `auth_source: agent_override`.
5. Confirm shared registration's old credential is not still
   accessible to overridden agents (run a request that the override
   should re-route, verify it didn't hit the old key — usually
   visible at the upstream provider's dashboard).

## See also

- [`agents-stack/docs/spec/v0.2.0.md`](https://github.com/SentientSwarm/agents-stack/blob/main/docs/spec/v0.2.0.md)
  — formal Phase G design.
- [`agent-identity-and-acl.md`](agent-identity-and-acl.md) — how
  agents authenticate and what audit fields are present today.
- [`trust-boundary.md`](trust-boundary.md) — operator vs agent
  vs upstream credential boundaries.
