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

## Subcommands

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
```

| Flag | Description |
|---|---|
| `--name` | Unique name. |
| `--allowlist a,b` | Comma-separated tool/model names the agent can call. |
| `--denylist x,y` | Comma-separated names the agent CANNOT call (deny wins when both match). |
| `agent set-cert-identity <public_id> <identity>` | Bind an mTLS certificate identity. |

`register` returns the bearer once. `revoke` sets the agent's row
to revoked; subsequent calls 401. Omitted/null/empty allowlists grant nothing.
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
| `--egress direct\|proxied` | Whether to route through the egress proxy. Defaults `proxied` server-side. |
| `--timeout-request <secs>` | Per-request timeout. Defaults server-side. |
| `--timeout-idle <secs>` | Per-read idle timeout. Defaults server-side. |
| `--body-limit <bytes>` | Max upstream response body size. Defaults 10 MiB. |
| `--metadata k=v` | Per-kind metadata. Repeatable. |
| `--metadata-file <path>` | Complete JSON metadata value, replacing existing metadata without merging. Mutually exclusive with `--metadata`. Supports nested `http_service` descriptions. |
| `--description '...'` | Free-form description. |

`enable` un-disables a previously-deleted seed row.

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

Phase F + Phase G. Requires `LOCKSMITH_OAUTH_SEALING_KEY` set in
the daemon's env.

```bash
locksmith oauth bootstrap <name> [--label <label>] --refresh-token <token>
locksmith oauth bootstrap <name> [--label <label>] --refresh-token-stdin
locksmith oauth status   <name> [--label <label>]
locksmith oauth revoke   <name> [--label <label>]
locksmith oauth list                                # NEW (Phase G)
```

`bootstrap` takes a refresh token obtained out-of-band (provider's
own OAuth flow) and registers it with locksmith. Daemon does an
inline first-refresh to verify, then seals refresh + access tokens
in `oauth_sessions` (AES-GCM with `LOCKSMITH_OAUTH_SEALING_KEY`).

**Phase G — `--label`**: distinguishes multiple sessions under one
registration, defaulting to `"default"`. Use distinct labels (e.g.,
`hermes`, `openclaw`) when bootstrapping per-agent OAuth from
different upstream accounts. Label must be ascii alphanumeric / `-`
/ `_`. Bootstrapping a non-default label when other labels exist
under the same registration emits a single-grant warning — see
[`concepts/per-agent-credentials.md`](concepts/per-agent-credentials.md).

`status` shows session state (present, label, scope, expires_at,
degraded, audit_session_id). Never leaks tokens.

`revoke` clears local session state. Idempotent. Provider-side
revocation deferred to v1.1+.

`list` enumerates all `(registration, label)` sessions across the
deployment. Useful for spotting orphaned per-agent sessions.

### `audit` — audit log queries (operator)

```bash
locksmith audit query [filters] [--format json]
locksmith audit tail            # streaming follow (post-v2; planned)
```

Filter flags:

| Flag | Description |
|---|---|
| `--since-ms <ms>` | Unix ms epoch (events at or after). |
| `--until-ms <ms>` | Unix ms epoch (events at or before). |
| `--agent <public_id>` | Filter to one agent. |
| `--tool <name>` | Filter to one tool/model name. |
| `--event-class <class>` | `auth\|proxy\|agent\|operator\|secret\|security\|admin`. |
| `--decision <d>` | `allowed\|denied\|error`. |
| `--limit <n>` | Default 100. |
| `--offset <n>` | Default 0. |

### `export` — operator-visible state snapshot (UC-10)

```bash
locksmith export agents              # JSON of agent records
locksmith export bootstrap-tokens    # JSON of bootstrap tokens
locksmith export tools               # JSON of legacy config.tools
```

Useful for backup or migration scripts.

### `mtls` — mTLS-related operations (M6)

```bash
locksmith mtls verify --ca <path> --cert <path>   # offline cert validation
locksmith mtls show-bindings                       # current cert→agent mapping
```

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
