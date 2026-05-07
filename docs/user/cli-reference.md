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
| `--format <fmt>` | `human` | Output format: `human` (table) / `json` / `yaml`. |

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
| `--header / --no-header` | `--header` | YAML comment header in stdout. |

Use `--no-header` for piping into a sealed-cred mechanism.

### `agent` — agent management (operator)

```bash
locksmith agent register --name <name> [--allowlist X,Y] [--denylist Z] [--cert-identity '...']
locksmith agent list
locksmith agent get <public_id>
locksmith agent modify --name <name> [--allowlist ...] [--denylist ...]
locksmith agent revoke <public_id>
```

| Flag | Description |
|---|---|
| `--name` | Unique name. |
| `--allowlist a,b` | Comma-separated tool/model names the agent can call. |
| `--denylist x,y` | Comma-separated names the agent CANNOT call (use one of allow/deny). |
| `--cert-identity '...'` | mTLS subject string (CN=..., O=..., etc.). |

`register` returns the bearer once. `revoke` sets the agent's row
to revoked; subsequent calls 401.

### `bootstrap` — bootstrap-token management (operator)

For pre-seeding agents that self-register via the bootstrap listener:

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

`put` flags:

| Flag | Description |
|---|---|
| `--upstream <url>` | Upstream URL the registration proxies to. Required. |
| `--auth <spec>` | Auth shape — see "Auth spec syntax" below. |
| `--egress direct\|proxied` | Whether to route through the egress proxy. Defaults `proxied` server-side. |
| `--timeout-request <secs>` | Per-request timeout. Defaults server-side. |
| `--timeout-idle <secs>` | Per-read idle timeout. Defaults server-side. |
| `--body-limit <bytes>` | Max upstream response body size. Defaults 10 MiB. |
| `--metadata k=v` | Per-kind metadata. Repeatable. |
| `--description '...'` | Free-form description. |

`enable` un-disables a previously-deleted seed row.

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

Phase F. Requires `LOCKSMITH_OAUTH_SEALING_KEY` set in the daemon's env.

```bash
locksmith oauth bootstrap <name> --refresh-token <token>
locksmith oauth bootstrap <name> --refresh-token-stdin
locksmith oauth status <name>
locksmith oauth revoke <name>
```

`bootstrap` takes a refresh token obtained out-of-band (provider's
own OAuth flow) and registers it with locksmith. Daemon does an
inline first-refresh to verify, then seals refresh + access tokens
in `oauth_sessions` (AES-GCM with `LOCKSMITH_OAUTH_SEALING_KEY`).

`status` shows session state (present, scope, expires_at, degraded,
audit_session_id). Never leaks tokens.

`revoke` clears local session state. Provider-side revocation
deferred to v1.1+.

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
| 1 | Generic error. |
| 2 | Usage error (missing flag, bad input). |
| 3 | Network / transport error. |
| 4 | Authentication / authorization error. |
| 5 | Server-side error (5xx from admin endpoint). |

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
