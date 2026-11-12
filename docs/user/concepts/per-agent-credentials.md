# Per-agent credentials

How to give two agents distinct upstream identities (separate API
keys, separate ChatGPT subscriptions) without proliferating
registrations. Phase G feature, paired with OAuth session labels.

## Explicit account selection

An authenticated agent needs both a reviewed finite allowlist of current HTTP
connection names and an explicit
account binding. The existing `agent_credential_overrides` row keyed by
`(agent_id, registration)` is that binding. Several agents may explicitly select
the same env reference or account. No row means **403 tool_not_allowed**; the
registration's credential template is never an implicit selection.

Omitting/nulling the allowlist grants nothing. Create the tool/model registration
first, then use `agent register --allowlist accounts` or
`agent modify "$AGENT_ID" --allowlist accounts`. Modification replaces the whole
set; `--allowlist -` clears it. Denylist entries still win. Unknown, disabled and
infra names cannot be newly granted or bound. Grants cover the entire ordinary
HTTP connection; operation, resource and method selectors are unsupported and
rejected.

A connection is identified by its registration name. Disabling/re-enabling keeps
its grants and selections but denies while disabled. Hard deletion removes both
in the same database write; recreating the name requires deliberate reapproval.
Changing upstream or egress also removes grants and bindings transactionally. Switching a route between declared backends
(`locksmith route switch`) is the exception: grants stay and bindings move
with the backend. See the CLI reference, "Route backends".
Description, timeout and credential-template edits retain identity. Reapprove the
finite allowlist and account after a destination replacement. Old bootstrap
scopes are also cleaned so enrollment cannot recover removed authority.

A selection-store failure or corrupt AuthSpec returns **503
credential_unresolved** before upstream dispatch. Missing or empty selected
header/bearer env values also return 503. These cases never use the registration's
startup-resolved credential or send an unauthenticated upstream request.

```
agent             registration       explicit binding                       effective
hermes-mini-1     lmstudio           bearer=SHARED_LM_KEY                   shared account X
openclaw-mini-1   lmstudio           bearer=SHARED_LM_KEY                   shared account X
third-agent      lmstudio           bearer=OTHER_LM_KEY                    account Y
unbound-agent    lmstudio           (absent)                               denied
```

Replacing a binding affects the next admission. Clearing it denies the next
request. Editing the registration credential template cannot repoint an existing
explicit env selection. Explicit `AuthSpec::None` is an owner-approved selection
and still obeys the agent's ACL; an absent or broken credential is never no-auth.

Use the [reviewed migration](migrating-account-bindings.md) for existing shared
account users. Rehearse the [saved actual-daemon smoke](../../development/explicit-account-bindings-smoke.md)
before cutover. See the [D1 change notes](../changes/explicit-account-bindings.md)
for the compatibility break and verification limits.

## Configuration, activation and admission

Operator `tool get/list` and `model get/list` report `configured`, `activation`
and `credential_readiness`. `active` means the full persisted registration
matches the runtime configuration. It does not mean any agent's selected account
is healthy; credential readiness remains `not_checked`. Disabled rows report
`disabled`; a saved row awaiting refresh reports `pending`.

A mutation whose database write succeeded but runtime refresh failed returns
HTTP 503 `connection_activation_failed`, with `saved: true` and
`activation: failed`. Inspect the saved registration before retrying. Repair the
catalog issue, then repeat the intended write or restart your deployment normally.
Changed stale connections deny with 503 `connection_not_active`; unrelated rows
whose contents still match can continue. Missing and disabled DB registrations
never fall back to same-name YAML configuration.

For each authenticated HTTP admission, one SQLite statement reads current agent
lifecycle/policy, registration and account reference. The proxy checks runtime
configuration against that snapshot before resolving only the selected source.
A revoke, disable, grant removal or binding change committed before this read
controls the request. Work admitted before a later change may finish, including
streaming responses; there is no stream-cancellation feature. Bearer rotation
rejects future authentication with the old token and does not cancel requests
already authenticated. Authenticated admission still rechecks revocation/expiry.

`/tools`, `/models` and personalized `/skill` show current granted, active DB
connections. JSON includes `account_selected`; selected source health is still
`not_checked`. An active listed connection may deny an absent account (403) or a
broken source (503). Config-only legacy discovery and `/admin/agent/tools` report
`configuration_only`, never per-agent credential readiness. `/readyz` remains an
instance/startup dependency probe and does not attest every agent's account.

## Setting an explicit binding

Use the public IDs returned by `agent register` as `HERMES_AGENT_ID`,
`OPENCLAW_AGENT_ID` and `DEBUG_AGENT_ID`; display names are not CLI IDs.

```bash
# Static credential — different env var for hermes vs openclaw.
locksmith agent set-credential "$HERMES_AGENT_ID"   lmstudio --auth bearer=LM_STUDIO_API_KEY_HERMES
locksmith agent set-credential "$OPENCLAW_AGENT_ID" lmstudio --auth bearer=LM_STUDIO_API_KEY_OPENCLAW

# Header injection (for `auth.kind = header` registrations).
locksmith agent set-credential "$HERMES_AGENT_ID" anthropic --auth header=x-api-key:ANTHROPIC_KEY_HERMES

# OAuth — pin to a specific session label (see below).
locksmith agent set-credential "$HERMES_AGENT_ID" codex --oauth-session hermes

# Explicitly permit credential-free use for an ACL-allowed agent.
locksmith agent set-credential "$DEBUG_AGENT_ID" lmstudio --no-auth

# Remove the binding (next request is denied).
locksmith agent unset-credential "$HERMES_AGENT_ID" lmstudio

# See all overrides for one agent.
locksmith agent credentials list "$HERMES_AGENT_ID"
```

The selected env var must exist and be nonempty in the daemon's environment
at request time. Bindings read it on the hot path, not at startup. A missing or
empty selected value fails with 503 before any upstream request. Reads return
AuthSpec references and timestamps, never the referenced credential value.

## Custody failures and legacy admission

Stored header/bearer bindings unseal only their selected `secret_ref`. Op
header/bearer bindings read only their selected cached reference; the request
never runs `op`. Missing, tombstoned, unreadable, wrongly sealed or empty values
return 503 before dispatch, including when another source is healthy.

Credentialed legacy `config.tools` routes require a real registered-agent
identity. M0/shared-bearer calls return **401 agent_identity_required** before
source resolution. `/readyz` returns 503 with the same reason and an upgrade
instruction when credentialed tools have no agent authenticator. Enable the
admin database/listener, register an agent, authenticate with that agent's bearer
or mTLS identity, and explicitly select its account. Credential-free routes
retain the current admission policy.

## Legacy file-backed credentials

A `config.tools` credential from `from_file_sealed` is not a directly selectable
AuthSpec source. An authenticated agent without a binding is denied even when
the daemon has successfully populated its legacy startup credential cache.
There is no automatic import or compatibility fallback.

An owner can deliberately import a file snapshot into the existing stored source:

1. Resolve the permission-restricted file using `FileSealedBackend` through
   `SecretResolver`, retaining its permission, read and cache checks.
2. Configure the corresponding registration with the intended upstream and
   header shape, then send the resolved bytes directly to the authenticated
   `PUT /admin/operator/tools/{name}/credential` endpoint over the admin transport.
   Its response supplies a `secret_ref`, never the value.
3. Explicitly select that reference with
   `PUT /admin/operator/agents/{agent}/credentials/{name}` and an
   `auth_spec` of `stored_header` with that header and returned `secret_ref`.
   Preserve prefixes: file bytes already containing `Bearer ` belong in a stored
   `authorization` header; a stored-bearer source would add its own prefix.
4. Verify the selected account at the upstream and reference-only admin reads.

This imports a snapshot; later file changes do not rotate the stored binding.
Another deliberate import and selection are required. The migration flags file-backed legacy sources for owner mapping and never
resolves or copies them. Its preview also skips prefixed env headers and legacy
strings whose wire transformation cannot be represented exactly. Preserve that
transformation deliberately in a new env/stored selection and verify the
receiving account before reopening traffic.

## OAuth labels

OAuth sessions live in the `oauth_sessions` table keyed on
`(registration_name, session_label)`. The default label is
`"default"` for bootstrap. Every account selection must name a nonempty label;
select `--oauth-session default` literally to use that session. Missing or empty
labels reject on operator writes and fail with 503 if already persisted.

`--oauth-session` supports model, tool and infra registrations. It copies the
registration's current OAuth client and endpoint metadata into the selection. Requests and refreshes use that selected mechanism,
including across template auth-kind or endpoint edits. Both PKCE and device-code
selections follow this rule. Old placeholder selections with empty metadata must
be explicitly selected again; they cannot inherit updated template metadata.

A missing, revoked, degraded, unreadable or empty selected session returns 503
without using another label. Expired-token requests share the existing
registration/label refresh lock. Inline admission requires every binding for the
same registration/label to agree with the admitted selection before using even
a cached token. Unavailable or conflicting metadata returns 503 with no token
exchange or upstream operation. Several agents can share a session with identical
explicit metadata. Background refresh visits only sessions with
consistent explicit selections; conflicting metadata for one session skips its
background refresh. Operator bootstrap still performs its explicit initial
exchange. No response or log includes token endpoint response bodies.

Per-agent OAuth uses two pieces:

1. **A session per selected account.** The account owner completes
   the upstream OAuth flow under their own provider account, then
   the operator bootstraps it under a label:
   ```bash
   locksmith oauth bootstrap codex --label hermes   --refresh-token-stdin < hermes-rt.txt
   locksmith oauth bootstrap codex --label openclaw --refresh-token-stdin < openclaw-rt.txt
   ```

2. **An explicit binding pointing at the label.** Agents sharing an account
   should select the same consistent label and OAuth metadata.
   ```bash
   locksmith agent set-credential "$HERMES_AGENT_ID"   codex --oauth-session hermes
   locksmith agent set-credential "$OPENCLAW_AGENT_ID" codex --oauth-session openclaw
   ```

Now `hermes-mini-1`'s requests resolve `oauth_sessions(codex,
"hermes")` and `openclaw-mini-1`'s resolve
`oauth_sessions(codex, "openclaw")`.

## The OAuth single-grant trap

Some providers invalidate an older refresh grant when the same account
authorizes the same client again. Do not assume separate labels are separate
accounts or independent grants. If agents intentionally share one account,
select the same label with identical client/endpoint metadata. Provider grant
policies must be verified with that provider; the local smoke does not test them.

**`oauth bootstrap` warns at the time of the trap.** When any
label (including `default`) is bootstrapped and other labels exist under
the same registration, the response carries a `warnings` field:

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
- `auth_source` — `"agent_override"` for explicitly bound agent requests.
  Credentialed identityless calls are denied before dispatch.
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

## Binding setup

For local setup (also see [getting started](../getting-started.md)):

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


### Upgrade existing shared-account users

Use the offline [reviewed migration workflow](migrating-account-bindings.md) to
inventory current allowed routes, preserve existing explicit choices and apply
only selected reference mappings. It requires a consistent SQLite backup and a
stopped daemon for cutover. Preview does not verify secret values or provider
availability; unresolved and identityless paths require deliberate owner mapping.
