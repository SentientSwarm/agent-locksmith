# `locksmith` CLI reference

The `locksmith` binary is the operator + agent self-service CLI.
It talks to a running `locksmithd` daemon via the admin UDS (default)
or admin HTTPS.

## Global flags

| Flag | Default | Description |
|---|---|---|
| `--socket <path>` | `/var/run/locksmith/admin.sock` | Admin UDS path. |
| `--admin-url <url>` | (none) | Admin HTTPS URL. Overrides `--socket`. |
| `--ca-bundle <path>` | (none) | PEM CA bundle for verifying admin HTTPS. |
| `--format <fmt>` | `table` | Output format: `table` / `json` / `yaml`. |

The CLI also reads:

- `LOCKSMITH_OP_TOKEN` — operator wire token (`lkop_...`).
- `LOCKSMITH_AGENT_TOKEN` — agent wire token (`lk_...`).
- `LOCKSMITH_ADMIN_URL` — same as `--admin-url`.
- `LOCKSMITH_CA_BUNDLE` — same as `--ca-bundle`.

## Guidance and diagnosis

The daemon's [`GET /skill`](agent-integration/skill-reference.md) distinguishes
HTTP connections from native MCP tools; it is not a new CLI subcommand. Native
repair uses existing `tool mcp show`, `agent mcp-grants show`, `agent credentials
list` and `audit query`. Status reads do not observe upstreams. Deliberate
observation/review/grant writes use the [native operator guide](operator/native-tool-review.md);
HTTP env/op/header/legacy OAuth options must not be used as native repair recipes.
Controlled native OAuth uses the owner-bound [select-oauth flow](operator/native-oauth.md).
Existing command syntax/help and authentication are unchanged.

## Subcommands

### `integration` and `tool from-definition` — offline authoring

`integration import --file FILE` saves one strict immutable definition;
`integration get ID --revision N` reads the exact revision.
`tool from-definition NAME --definition ID --revision N --auth-profile ID
--upstream URL [--allow-private-destination]` creates a disabled pinned native
connection. No provider request, account selection, credential or grant occurs.
General edits/enable remain refused for these derived instances.

`tool activate-definition NAME --if-match REVISION [--compact]
[--oauth-profile PROFILE_ID]` deliberately promotes a supported local pin; read
the opaque `definition_control.revision` from `tool get NAME --format json`.
Only controlled OAuth declarations use the explicit trusted profile option.
`tool deactivate-definition NAME --if-match REVISION` disables a pin and clears
its local authority while retaining sealed accounts. Both commands accept
`--format json`. A stale revision refuses; use a fresh GET after conflicts or an
uncertain outcome. An exact current-state retry only reconciles the runtime
catalog. Activation alone grants nothing: repair ACL, explicit account selection,
observation, reviews and finite grants, then use fresh sessions. See
[complete schema, examples and repair limits](operator/integration-definitions.md).


### `bootstrap-operator` — mint operator credential (offline)

```bash
locksmith bootstrap-operator --name <name>
```

Self-contained. Doesn't talk to a daemon. Generates a fresh
structured token (`lkop_<public_id>.<secret>`), argon2-hashes the
secret, writes operators.yaml content to **stdout**, prints the
cleartext wire token to **stderr** ONCE.

| Flag | Default | Description |
|---|---|---|
| `--name <name>` | `default` | Operator display name (audit attribution). |
| `--header true\|false` | `true` | Include YAML comment header in stdout. |

Use `--header false` for piping into a sealed-cred mechanism.

### `agent` — agent management (operator)

```bash
locksmith agent register --name <name> [--allowlist X,Y] [--denylist Z]
locksmith agent list
locksmith agent get <public_id>
locksmith agent modify <public_id> [--allowlist ...] [--denylist ...]
locksmith agent revoke <public_id>
locksmith agent prune-revoked [--dry-run]
```

| Flag | Description |
|---|---|
| `--name` | Unique name. |
| `--allowlist a,b` | Comma-separated tool/model names the agent can call. |
| `--denylist x,y` | Comma-separated names the agent CANNOT call (deny wins when both match). |
| `agent set-cert-identity <public_id> <identity>` | Bind an mTLS certificate identity. |

`register` returns the bearer once. `revoke` sets the agent's row
to revoked; subsequent calls 401. In the same write it removes the agent's
account bindings (including those stashed for inactive route backends), its
grants and its native grant sets, and audits `agent_revoke` with their counts.
`prune-revoked` removes what revokes made before this change left behind,
listing each agent's bound routes but never credential values; `--dry-run`
reports without changing anything, and a second run finds nothing. Omitted/null/empty allowlists grant nothing.
Names must be existing enabled tool/model registrations. `modify --allowlist`
replaces the full set; `--allowlist -` clears it. Omitted modify fields stay
unchanged. `grants_reviewed` distinguishes old policies needing offline review;
it does not attest activation or credential readiness. Denylist still wins.

#### Explicit account bindings

```bash
locksmith agent set-credential <public_id> <reg> --auth bearer=<ENV_VAR>
locksmith agent set-credential <public_id> <reg> --auth header=<Header>:<ENV_VAR>
locksmith agent set-credential <public_id> <reg> --no-auth
locksmith agent set-credential <public_id> <reg> --oauth-session <label>
locksmith agent select-oauth <public_id> <reg> --label <label> --if-match <account-revision>
locksmith agent unset-credential <public_id> <reg>
locksmith agent credentials list <public_id>
```

`set-credential` upserts an explicit account binding for one agent on one
registration. After the current ACL check, the proxy uses only that selected
source; an absent binding is denied rather than inheriting the template. See
[`concepts/per-agent-credentials.md`](concepts/per-agent-credentials.md)
for the design and the OAuth single-grant trap.

`--oauth-session` requires a nonempty explicit label (`default` is literal). It
copies the selected registration's current OAuth metadata into the binding.
Later template changes do not redirect that binding's refresh exchange. Old
empty-placeholder bindings require deliberate re-selection.

`unset-credential` is idempotent — removing an absent binding returns success.
After clearing, subsequent requests to that registration are denied until an
explicit binding is set again.

### `bootstrap` — bootstrap-token management (operator)

For pre-seeding agents that self-register via the bootstrap listener. Omitted
allowlist means no grants. Historical unreviewed tokens cannot enroll; re-mint
with current finite names after upgrade:

```bash
locksmith bootstrap mint [--allowlist X,Y] [--reusable] [--expires-at <unix-secs>]
locksmith bootstrap list
locksmith bootstrap revoke <public_id>
```

| Flag | Description |
|---|---|
| `--allowlist a,b` | Constrains the agent's ACL at register time. |
| `--reusable` | Allow multiple consumes (default: single-use). |
| `--expires-at <secs>` | Unix epoch expiration. |

### `tool` / `model` / `infra` — catalog management (operator)

Three parallel subcommand families. Same shape, different `kind`.

```bash
locksmith {tool,model,infra} list
locksmith {tool,model,infra} get <name>
locksmith {tool,model,infra} put <name> --upstream URL --auth <spec> [opts]
locksmith {tool,model,infra} delete <name>
locksmith {tool,model,infra} enable <name>
```

Catalog reads report `configured`, `activation` (`active`, `pending`, `disabled`)
and `credential_readiness: not_checked`. A saved write whose runtime refresh
fails returns 503 `connection_activation_failed` / CLI exit 1. Inspect the saved
entry before retrying; repair and repeat the intended write or restart normally.
Changing upstream/egress or deleting/recreating a name clears grants and account
selections; disable/re-enable retains them. `delete` on a seeded entry disables
it; on an operator-created entry it hard-deletes. No active entry alone proves an
agent's selected account works.

An invalid tool/model URL returns HTTP 400 `invalid_upstream` / CLI exit 1 before
saving or activation. The existing row, grant and account selection remain
unchanged. See [operator onboarding](operator/connector-onboarding.md) for seed
validation and compatibility details.

`put` flags:

| Flag | Description |
|---|---|
| `--upstream <url>` | Required base URL. Tool/model require absolute HTTP(S), with no userinfo, query or fragment; localhost/IP/private hosts and path prefixes are supported. Infra retains its existing contract. |
| `--auth <spec>` | Auth shape — see "Auth spec syntax" below. |
| `--egress direct\|proxied` | Whether to route through the egress proxy. Defaults `direct`; native currently requires `direct`. |
| `--timeout-request <secs>` | Per-request timeout. Defaults server-side. |
| `--timeout-idle <secs>` | Per-read idle timeout. Defaults server-side. |
| `--body-limit <bytes>` | Max size of the agent's request body forwarded upstream. A larger body returns 400 `bad_request`. Defaults 10 MiB. |
| `--metadata k=v` | Per-kind metadata. Repeatable. |
| `--protocol http\|mcp_streamable_http` | Registration protocol; omitted means HTTP, including full replacement updates. Native is tool-only. |
| `--mcp-config-file <path>` | Strict native JSON config (`protocol_version`, optional `allow_private_destination`), required for native. See [native setup](operator/native-mcp.md). |
| `--metadata-file <path>` | Complete JSON metadata value, replacing existing metadata without merging. Mutually exclusive with `--metadata`. Supports nested `http_service` descriptions. |
| `--description '...'` | Free-form description. |
| `--upstream-ca-file <path>` | PEM trust anchors for this route only (`-` reads stdin). See "Per-route upstream CA" below. |
| `--profile <generic\|openai-codex-responses>` | Request profile: which provider wire behaviour the route gets. See "Route profiles" below. |

`enable` un-disables a previously-deleted seed row.

### Route profiles

A route's profile selects provider-specific wire behaviour. With
`openai-codex-responses`, Locksmith applies the Codex Responses behaviours:
the `ChatGPT-Account-ID` header from the selected OAuth session, the
`/responses` body fix-ups and the required `OpenAI-Beta` and `originator`
headers. With `generic`, it applies none of them.

Without `--profile`, the profile is inferred from the upstream: Codex for a
`/backend-api/codex` upstream, generic otherwise. `get` shows the effective
`profile` and whether it was `explicit` or `inferred` (`profile_source`).
Omitting `--profile` on a later `put` returns the route to inference.
Changing a profile does not change the destination, so grants and account
selections are kept.

```bash
# Codex behaviour for a route whose upstream is an account broker
locksmith model put codex-pool --upstream http://127.0.0.1:43210 \
  --auth bearer=CODEX_POOL_KEY --egress direct --profile openai-codex-responses
```

### Route backends

A tool or model route can declare several **backends** (destinations) and
switch between them. Grants stay on the route; account bindings belong to a
backend. Use this to move a route onto an account broker without re-granting
every agent.

```bash
locksmith route backend put codex broker --upstream http://127.0.0.1:43210 \
  --auth bearer=CODEX_POOL_KEY --egress direct
locksmith route backend list codex          # active backend and revision
locksmith route switch codex --backend broker --if-match <revision>
```

- Before its first switch a route has one implicit backend, `primary`: its
  current destination. A switch records the current destination under the
  active backend's name, so `route switch codex --backend primary` goes back.
- Agents keep their grant. Their bindings are stashed with the old backend
  and restored when it becomes active again. An agent with no binding on the
  new backend is refused (403 `tool_not_allowed`, audit
  `account_binding_missing`) until you select an account for it.
- `--if-match` is the route revision from `route backend list`. Editing or
  deleting any backend also moves the revision, so a switch cannot land on
  a destination changed after you read it. A missing revision is 428
  `if_match_required`, one that is not a number is 400 `if_match_invalid`,
  and a stale one is 409 `revision_conflict` and changes nothing.
- `route backend list` and `get` show the active backend as the route
  currently has it, so an edit made with `tool|model put` shows there too.
- Each switch writes a `route_backend_switched` security audit event with
  the upstream, egress and CA fingerprint before and after, and reports
  `profile_before` / `profile_after`. Backend edits write
  `route_backend_put` and `route_backend_deleted`. A route without an explicit
  `--profile` infers it from the new upstream, so set the profile explicitly
  on routes that move to a broker.
- The active backend is edited with `tool|model put` as before: changing
  its upstream, egress or CA still revokes grants and bindings. Changing an
  inactive backend's destination discards only the bindings stashed for it.
- Not switchable (409 `route_not_switchable`): native MCP connections,
  `infra` and definition-pinned routes. OAuth backends are refused (409
  `backend_auth_unsupported`) because OAuth sessions are keyed by route.
  The active backend cannot be replaced, deleted or re-selected (409
  `active_backend`).

### Broker routes

A **broker** is a destination that holds the provider accounts itself and
picks one per request. Locksmith authenticates to it with one route-level
key, names the calling agent, and never sends an agent's own credential.

```bash
locksmith model put codex-pool --upstream http://127.0.0.1:43210 \
  --egress direct --broker \
  --attribution-header x-account-label --health-path /healthz
printf '%s' "$POOL_KEY" | locksmith model set-key codex-pool   # stdin, never argv
locksmith agent set-credential "$AGENT_ID" codex-pool --broker
```

- **Key.** The route's auth is the broker key: `stored_bearer` or
  `stored_header` (sealed with `set-key`, which reads stdin; `--header H`
  sends it in `H` instead of `Authorization: Bearer`), or `op_bearer` /
  `op_header`. A broker `put` without `--auth` keeps the route's key, so
  editing the spec never discards it; a new broker starts with none. The
  key stays only with its destination: a `put` that changes the upstream,
  egress or CA without `--auth` is refused (400 `invalid_broker`), and one
  that races a key change or re-point is refused (409 `broker_key_changed`;
  re-read and retry). `--auth none` clears the key. Without a key every request fails closed
  (503 `credential_unresolved`). Env and OAuth keys are refused (400
  `invalid_broker`).
- **Selection.** Agents select a broker route with `--broker` (stored as
  `{"kind":"broker"}`). It is the only selection a broker route accepts, and
  a broker selection is refused on an ordinary route. An agent granted the
  route but not bound is refused (403 `tool_not_allowed`, audit
  `account_binding_missing`).
- **Identity.** The broker receives the caller's public id in
  `X-Locksmith-Agent` (`--identity-header H` renames it,
  `--no-identity-header` omits it). Any copy the agent sends of the
  configured header or of `X-Locksmith-Agent` is stripped, including when
  the identity is renamed or omitted. The header cannot be a credential
  header (`Authorization`, `X-Api-Key`), the key header, or a reserved
  name (below).
- **Reserved header names.** Hop-by-hop and framing headers (`Host`,
  `Content-Length`, `Transfer-Encoding`, `Connection`, `Keep-Alive`,
  `Proxy-Connection`, `TE`, `Trailer`, `Upgrade`, `Proxy-Authorization`)
  and the headers Locksmith sets (`OpenAI-Beta`, `originator`,
  `ChatGPT-Account-ID`) are refused as an identity header (400
  `invalid_broker`) and as the credential header of `tool|model set-key
  --header`, `route backend set-credential --header` and the per-agent
  `PUT /admin/operator/agents/{agent}/credentials/{reg}/credential` (400).
  `--header` works the same on any route, broker or not: `tool|model
  set-key --header H` seals the key as `stored_header`, sent as `H: <key>`;
  without it the key is sent as `Authorization: Bearer <key>`.
- **Attribution.** `--attribution-header H` copies the broker's response
  header `H` into audit as `details.broker_account` when it is 1-64
  printable ASCII characters without spaces; otherwise audit records
  `broker_account_invalid: true`, as it also does when the broker repeats
  the header (a repeated header names no single account).
  `--attribution-sensitive` records
  `sha256:<hex>` instead. The header still reaches the agent.
- **Health.** `--health-path /p` probes `GET <upstream>/p` with the broker
  key every `--health-interval` seconds (5-3600, default 30), expecting
  `--health-status` (default 200) within 5 s. The probe never follows a
  redirect: a 3xx is the result, so `--health-status 302` can match. After
  a failed probe the route answers 503 `backend_unavailable` without
  dispatch, until a probe passes. A route not yet probed is admitted.
  Transitions are logged as `broker_down` (warn) and `broker_up` (info).
  A key that cannot be materialized is not a failed probe: the route is
  not probed, its health stays unknown, `broker_key_unresolved` (warn) is
  logged once, and requests fail on the key (503 `credential_unresolved`).
  These events use the `broker` component of the operational log
  (`GET /admin/operator/logs`). A selection or key failure is reported
  before a down broker. `tool|model get` shows the last probe as
  `health` (`status`, `http_status`, `checked_at`; `null` before the first).
  `/readyz` reports `brokers: {up, down, unknown}` counts only, and a down
  broker never fails readiness.
- **Audit.** Proxy rows carry `auth_mode: broker`, `auth_source: broker`,
  `broker_key_mode` (the key's kind, never its value) and
  `backend_kind: broker`.
- An existing route cannot change between broker and ordinary destination
  in place (409 `broker_kind_change`). Declare a broker backend and switch
  to it instead:

```bash
locksmith route backend put codex pool --upstream http://127.0.0.1:43210 \
  --auth none --egress direct --broker
printf '%s' "$POOL_KEY" | locksmith route backend set-credential codex pool
locksmith route switch codex --backend pool --if-match <revision>
locksmith agent set-credential "$AGENT_ID" codex --broker
```

  Upstream bindings are stashed with the old backend and never reach the
  broker. Switching back restores them. `route backend set-credential`
  seals an inactive backend's key and moves the route revision. The active
  backend's key is set with `tool|model set-key`.

### Per-route upstream CA

An HTTPS upstream behind a private CA can carry its own trust anchors:

```bash
locksmith model put private-llm --upstream https://10.0.0.5/v1 \
  --auth bearer=PRIVATE_LLM_KEY --upstream-ca-file ca.pem
```

- The route trusts **only** these certificates. Public roots and the
  global `tls.upstream_ca_bundle` are not used for it, and other routes do
  not trust them.
- Any certificate in the file is a trust anchor, so an intermediate alone
  works when the root is unavailable (partial chain). Supply the issuing CA,
  not the server's own certificate.
- The file must hold 1–16 PEM certificates (64 KiB at most) and nothing
  else. The upstream must be `https://` and the route `--protocol http`.
  Anything else returns 400 `invalid_upstream_ca` / CLI exit 1.
- Reads show `upstream_ca: {sha256, certificates}`, never the PEM.
- `put` replaces the whole registration, so repeat the flag on every
  `put`; omitting it removes the CA.
- Changing or removing the CA clears every grant and account binding for
  the route, as an upstream change does. Re-grant and re-bind afterwards.
- Verification is never disabled. A stored CA that cannot be loaded leaves
  the route with no trust anchors, so requests fail (502) instead of
  falling back to public roots.

The optional public `metadata.http_service` member is validated before saving;
malformed descriptions return HTTP 400 `invalid_http_service` / CLI exit 1.
File read/JSON syntax failures are local CLI exit 2. See
[HTTP service authoring](operator/connector-onboarding.md#publish-a-service-description).

### Auth spec syntax (`--auth`)

| Form | Variant | Effect |
|---|---|---|
| `none` | `AuthSpec::None` | No header injection (operator-stated authless). |
| `header:NAME=ENV_VAR` | `AuthSpec::Header { header: NAME, env_var: ENV_VAR }` | Inject `NAME: <env-var-value>`. |
| `bearer=ENV_VAR` | `AuthSpec::Bearer { env_var: ENV_VAR }` | Inject `Authorization: Bearer <env-var-value>`. |

Per-kind validation:

- `kind=tool` requires `--auth` (use `none` for authless).
- `kind=model` requires `--auth` (`none` accepted for LAN-local models).
- `kind=infra` accepts no `--auth` flag (defaults to `None`).

OAuth shapes (`oauth_pkce`, `oauth_device_code`) come from the seed
catalog — operator overrides are typically just `--upstream` for
host-specific routing. The OAuth credential management itself uses
`locksmith oauth ...`.

### `oauth` — OAuth session management (operator)

The legacy Phase F + Phase G commands below require
`LOCKSMITH_OAUTH_SEALING_KEY` in the daemon's environment. They do not manage
controlled consent accounts.

```bash
locksmith oauth bootstrap <name> [--label <label>] --refresh-token <token>
locksmith oauth bootstrap <name> [--label <label>] --refresh-token-stdin
locksmith oauth device-login <name> [--label <label>] [--replace]   # ChatGPT plan (codex)
locksmith oauth status   <name> [--label <label>]
locksmith oauth revoke   <name> [--label <label>]
locksmith oauth list                                # legacy sessions only
```

`bootstrap` takes a refresh token obtained out-of-band (provider's
own OAuth flow) and registers it with locksmith. Daemon does an
inline first-refresh to verify, then seals refresh + access tokens
in `oauth_sessions` (AES-GCM with `LOCKSMITH_OAUTH_SEALING_KEY`).

`device-login` signs a ChatGPT-plan (codex) session in without a refresh
token ever reaching the operator's shell. It prints a URL and a one-time
code, and waits while you sign in on any browser; the daemon runs OpenAI's
device authorization and the code exchange itself, then stores the session
the same way `bootstrap` does. A session that needs reconnecting (degraded
or refresh pending) is replaced in place, so agent bindings to that label
keep working. A healthy session is replaced only with `--replace`. If the
sign-in succeeds but the first refresh fails, the replaced session is gone
and the label reads `reconnect_required` or absent; run the command again,
which needs no `--replace` either way. Like `bootstrap`, completion warns
when other labels exist under the registration, because one ChatGPT account
signed in under two labels can invalidate the other. Only OpenAI's device
dialect is supported; other registrations get `device_login_unsupported`.
The admin API is `POST /admin/operator/oauth/<name>/device-login?label=`
(body `{"replace": bool}`, returns `attempt`, `verification_url`,
`user_code`, `interval`) and `GET .../device-login/<attempt>`, which polls
once and returns `pending` or `complete` with the session status. Attempts
are held in memory, expire after 15 minutes and do not survive a restart. At most
16 are pending at once (429 `too_many_device_logins`). Revoking the label
ends its pending logins, and a login fails with 409 `authority_changed`
before any code is exchanged when its registration, or any agent binding that
selects the label, no longer names the issuer and client it used, so tokens only ever go to the issuer that issued them.

**Phase G — `--label`**: distinguishes multiple sessions under one
registration, defaulting to `"default"`. Use distinct labels (e.g.,
`hermes`, `openclaw`) when bootstrapping per-agent OAuth from
different upstream accounts. Label must be ascii alphanumeric / `-`
/ `_`. Bootstrapping any label (including `default`) when other labels
exist under the same registration emits a single-grant warning — see
[`concepts/per-agent-credentials.md`](concepts/per-agent-credentials.md).

`status` shows session state (present, label, scope, expires_at,
degraded, audit_session_id). Never leaks tokens.

`revoke` clears local session state. Idempotent. Provider-side
revocation deferred to v1.1+.

`list` enumerates legacy `(registration, label)` sessions across the
deployment. Controlled owner-bound rows are filtered out; legacy status,
revoke and bootstrap refuse those rows.

For the optional owner-bound [controlled](operator/oauth-consent.md) or
[hosted Linear](operator/hosted-linear.md) consent profiles, use `oauth connect`,
`oauth attempt-status`, `oauth cancel`, `oauth account-status`,
`oauth refresh` and `oauth disconnect`. Refresh requires `--label` and the current
`--if-match` revision; it is manual and grants no agent access. The [controlled consent guide](operator/oauth-consent.md)
specifies their flags, owner checks, configuration and local disconnect
precondition. A `connected_unbound` account does not authorize agent calls.

### `audit` — audit log queries (operator)

```bash
locksmith audit query [filters] [--format json]
locksmith audit tail            # streaming follow (post-v2; planned)
```

Filter flags:

| Flag | Description |
|---|---|
| `--since-ms <ms>` | Unix ms epoch (events at or after). |
| `--until-ms <ms>` | Unix ms epoch (events before; exclusive). |
| `--agent <public_id>` | Filter to one agent. |
| `--tool <name>` | Filter to one tool/model name. |
| `--event-class <class>` | `proxy\|operator\|security`. Other values return 400 `invalid_event_class`. |
| `--decision <d>` | `allowed\|denied\|error`. |
| `--limit <n>` | Default 100. |
| `--offset <n>` | Default 0. |

### `export` — operator-visible state snapshot (UC-10)

```bash
locksmith export agents --format json   # snapshot of agent records
```

`agents` is the only export.

Useful for backup or migration scripts.

### `mtls` — mTLS-related operations (M6)

```bash
locksmith mtls revoke <serial> --blocklist-path <path> [--reason '...']
locksmith mtls list-blocklist --blocklist-path <path>
locksmith mtls crl-status
```

`revoke` appends a hex cert serial (case-insensitive) to the local emergency
blocklist file; `--reason` is written as a `# comment` line above it.
`list-blocklist` prints the serials in that file. Both edit or read the file
directly and do not contact the daemon. `--blocklist-path` must match
`listen.mtls.blocklist_path`; the daemon picks up changes on its next reload
poll.

`crl-status` does not contact the daemon and reports no CRL state. Read CRL
state from the daemon log (`CRL applied`, `CRL refresh failed; prior snapshot
retained`, `CRL refused` lines) and from `mtls-crl-cache.pem`, the last good
CRL, stored beside the database file.

### Self-service (agent token required)

```bash
locksmith status                            # show your agent's state
locksmith rotate [--current-secret <secret>]  # rotate your bearer
```

These don't need an operator token — they take the agent's bearer
from `LOCKSMITH_AGENT_TOKEN`.

## Exit codes

Per SPEC §4.7.2:

| Code | Meaning |
|---|---|
| 0 | Success. |
| 1 | Generic, transport or other server error (including HTTP 5xx). |
| 2 | Usage error (missing flag, bad input). |
| 3 | Authentication / authorization error (missing credentials or HTTP 401/403). |
| 4 | Not found (HTTP 404). |
| 5 | Conflict (HTTP 409), or offline migration drift. |

## Common workflows

### First-time deploy (standalone)

```bash
locksmith bootstrap-operator --name dev > operators.yaml
locksmithd --config config.yaml &
export LOCKSMITH_OP_TOKEN=lkop_...
locksmith agent register --name dev-agent --allowlist anthropic
```

### Daily ops

```bash
# What's registered?
locksmith model list
locksmith tool list

# Who's calling what?
locksmith audit query --since-ms $(($(date +%s) * 1000 - 3600000))

# Who's getting denied?
locksmith audit query --decision denied --since-ms $(($(date +%s) * 1000 - 86400000))
```

### Agent rotation

```bash
locksmith agent revoke <old_public_id>
locksmith agent register --name <name> --allowlist <list>
# Distribute new bearer to the agent host.
```

### Tool override

```bash
locksmith model put lmstudio --upstream http://mac-server.lan:1234 --auth bearer=LM_STUDIO_API_KEY
```

### OAuth bootstrap

```bash
# After provider's own OAuth flow gives you a refresh token:
locksmith oauth bootstrap codex --refresh-token "$REFRESH_TOKEN"
locksmith oauth status codex
```

## See also

- [getting-started.md](getting-started.md) — first-contact recipe.
- [architecture.md](architecture.md) — what the daemon does on each
  request.
- [`agent-integration/`](agent-integration/) — wiring agents (hermes,
  openclaw) at the wire level.


## Offline account-binding migration

`locksmith migrate-bindings preview --grants --database EXISTING_DB [--legacy-config YAML]`
prints a deterministic reference-only JSON plan. Review it privately and change
only `selected` flags on desired binding proposals and reviewed finite `grants`
rows. A review-only or empty-grant apply can insert zero bindings. Without
`--grants`, the account-only format does not review historical policy. Then run
`locksmith migrate-bindings apply --database EXISTING_DB --plan REVIEWED_JSON`
with the same optional `--legacy-config`. The daemon must be stopped for cutover;
back up SQLite safely, including committed WAL contents. No operator token,
credential resolution, file import or remote API is used. Relevant drift returns
exit 5 with no partial changes; an unchanged repeat inserts zero rows.

See the [migration procedure](concepts/migrating-account-bindings.md) for backup,
review, unavailable-source handling, verification and rollback consequences.

For a runnable local setup see [getting started](getting-started.md). Execute
the [saved cutover smoke](../development/explicit-account-bindings-smoke.md)
to verify daemon/CLI setup, selection, clear/repair and offline migration.

## Native fixed context and diagnosis

`tool mcp review CONNECTION --agent AGENT_ID --file PATH` accepts optional fixed
nonsecret `context` in its strict JSON request. Saving a review grants nothing.
`tool mcp show` and `agent mcp-grants show` return safe current-state diagnosis
without network requests. See [review, repair and downgrade limits](operator/native-context.md).

Native `tool put --mcp-config-file` accepts optional `compact:true` (default false).
Configure before grants: changing MCP config clears connection/bootstrap scopes,
selections, observations, reviews and tool grants. See [compact MCP](agent-integration/compact-mcp.md)
for the complete agent contract and actual prior-daemon startup cost.

Native MCP configuration may explicitly set `contract_policy:"finite-v2"`.
Eligible definition promotion accepts `--contract-policy finite-v2` and repeatable
`--selected-tool NAME` (manual configuration uses `selected_tools`); changing an
active pin requires deactivation and deliberate repair. The review JSON must
repeat the policy, and open-empty input requires `input_restriction:"empty-arguments"`.
See [exact policy, projection and old-reader limits](operator/native-contract-policy.md).

### Confidential OAuth client custody

See [Slack OAuth](operator/slack-oauth.md) for `oauth client set --secret-stdin`,
`oauth client status`, and `oauth client retire`. All require the connection name,
`--profile` and `--client-generation`. Set seals a new immutable owner generation;
reads never reveal the value. Slack `oauth connect` requires explicit
`--scopes search:read.public,channels:history`.
