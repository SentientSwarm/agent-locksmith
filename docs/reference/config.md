# Configuration file reference

`locksmithd --config <file>` reads one YAML file. This page lists every key
it accepts.

- The file is read once at startup. Any change needs a restart.
- Unknown keys are refused, so a typo stops the daemon instead of being
  ignored.
- `${VAR}` anywhere in the file is replaced with that environment variable
  before parsing. An unset variable becomes an empty string.
- Services, agents, grants, account selections, stored credentials, OAuth
  sessions and rate limits are not configured here. They live in the database
  and change live through the `locksmith` CLI; see the
  [CLI reference](cli-reference.md).

The repository's [`config.example.yaml`](../../config.example.yaml) is a
commented starting point.

## Complete example

Every optional block, with its default values where it has them. The tests
parse this block, so it is always a valid configuration.

<!-- config-reference:complete -->
```yaml
listen:
  host: "127.0.0.1"
  port: 9200
  auth_mode: bearer            # bearer | mtls | both
  admin_socket:
    path: "/var/run/locksmith/admin.sock"
  admin_https:
    enabled: false
    host: "127.0.0.1"
    port: 9201
    cert_path: "/etc/locksmith/tls/admin.crt"
    key_path: "/etc/locksmith/tls/admin.key"
    auth_mode: bearer
    mtls:
      ca_bundle_path: "/etc/locksmith/tls/operator-ca.pem"
  mtls:
    ca_bundle_path: "/etc/locksmith/tls/agent-ca.pem"
    server_cert_path: "/etc/locksmith/tls/agent.crt"
    server_key_path: "/etc/locksmith/tls/agent.key"
    crl_url: "https://ca.example.com/crl.der"
    crl_refresh_interval_seconds: 3600
    blocklist_path: "/etc/locksmith/tls/blocklist.txt"
    blocklist_reload_interval_seconds: 30
  bootstrap_only:
    enabled: false
    host: "127.0.0.1"
    port: 9202
    cert_path: "/etc/locksmith/tls/bootstrap.crt"
    key_path: "/etc/locksmith/tls/bootstrap.key"

operator_credentials_path: "/etc/locksmith/operators.yaml"

database:
  path: "/var/lib/locksmith/locksmith.db"

audit:
  retention_days: 90
  sweep_interval_seconds: 3600
  jsonl_path: "/var/log/locksmith/audit.jsonl"
  jsonl_max_bytes: 104857600
  jsonl_keep_files: 14

operational_log:
  retention_days: 30
  sweep_interval_seconds: 3600

credential_store:
  tombstone_retention_days: 7
  orphan_grace_seconds: 3600
  sweep_interval_seconds: 3600

egress_proxy: "http://127.0.0.1:8888"
egress:
  mode: pipelock               # pipelock | external

tls:
  upstream_ca_bundle: "/etc/locksmith/tls/internal-ca.pem"

inspection:
  sidecars:
    - name: promptguard
      socket: "/run/locksmith-inspector/inspector.sock"
      timeout_ms: 1000
  routes:
    - route: search
      request:
        scanners: [dlp]
        on_hit: block            # pass | flag | redact | block
        on_error: fail_closed    # fail_open | fail_closed
        max_scan_bytes: 1048576
      response:
        scanners: [injection, "sidecar:promptguard"]
        on_hit: flag
        on_error: fail_open

mcp:
  upstream_ca_bundle: "/etc/locksmith/tls/internal-ca.pem"
  allowed_hosts: ["localhost", "127.0.0.1", "[::1]"]
  allowed_origins: []
  ingress: 128
  sessions: 256
  sessions_per_agent: 16
  sessions_per_connection: 16
  messages: 256
  streams: 4
  handshake_ms: 5000
  lifetime_ms: 900000
  idle_ms: 300000
  request_ms: 10000
  response_ms: 60000
  request_bytes: 262144

logging:
  level: info
  file: "/var/log/locksmith/locksmithd.log"

shutdown:
  drain_window_seconds: 30
```

`oauth_consent` and the legacy `tools` and `inbound_auth` keys are described
in their own sections below; they are left out of the example because each
needs service-specific values.

## `listen`

The agent listener and the admin listeners.

| Key | Default | Meaning |
|---|---|---|
| `host` | `127.0.0.1` | Address of the agent listener. A value that is not an IP address falls back to `127.0.0.1`. |
| `port` | `9200` | Port of the agent listener. |
| `auth_mode` | `bearer` | How agents authenticate. `bearer`: a Locksmith token in `Authorization`. `mtls`: a client certificate, and a bearer header is refused. `both`: a certificate if one is presented, otherwise a bearer token. |
| `admin_socket.path` | none | Unix socket for the operator CLI, created with mode 0660. It turns on the database, per-agent identity and the admin API. Without it Locksmith runs in [legacy mode](#legacy-mode). |
| `mtls` | none | Required when `auth_mode` is `mtls` or `both`; see below. |
| `admin_https` | none | Optional admin listener over HTTPS; see below. |
| `bootstrap_only` | none | Optional enrolment listener; see below. |

### `listen.mtls`

| Key | Default | Meaning |
|---|---|---|
| `ca_bundle_path` | required | PEM bundle. Agent certificates must chain to one of these CAs. |
| `server_cert_path`, `server_key_path` | required for `mtls`/`both` | The certificate and key the agent listener presents. The daemon will not start if either is missing or unreadable. |
| `crl_url` | none | A CRL to fetch in the background. |
| `crl_refresh_interval_seconds` | `3600` | How often to refetch the CRL. |
| `blocklist_path` | none | Emergency blocklist: one hex certificate serial per line. Re-read while running. |
| `blocklist_reload_interval_seconds` | `30` | How often to re-read the blocklist. |

See the [mTLS onboarding](../operator/runbooks/mtls-onboarding.md) and
[revocation](../operator/runbooks/mtls-revocation.md) runbooks.

### `listen.admin_https`

Serves the same admin API as the socket, for remote operators.

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `false` | Nothing is bound unless this is `true`, so the block can sit in the file unused. |
| `host` | `127.0.0.1` | Listener address. |
| `port` | `9201` | Listener port. |
| `cert_path`, `key_path` | required | Server certificate chain and PKCS#8 key, loaded at startup. |
| `auth_mode` | `bearer` | How operators authenticate: `bearer`, `mtls` or `both`. |
| `mtls.ca_bundle_path` | required for `mtls`/`both` | CA bundle for operator client certificates. |

See the [remote management runbook](../operator/runbooks/remote-management.md).

### `listen.bootstrap_only`

A TLS listener that accepts only agent enrolment
(`POST /admin/agent/register`), for mTLS-only fleets where new agents have no
certificate yet. Enabling it requires `listen.admin_socket`.

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `false` | Bound only when `true`. |
| `host` | `127.0.0.1` | Listener address; must be an IP address. |
| `port` | `9202` | Listener port. |
| `cert_path`, `key_path` | required | Server certificate and key. |

## Admin substrate

These are required together with `listen.admin_socket`. `database.path` is
also required when `listen.auth_mode` is `mtls` or `both`.

| Key | Meaning |
|---|---|
| `operator_credentials_path` | YAML file of operator credentials (hashes only), written by `locksmith bootstrap-operator`. |
| `database.path` | The SQLite database. Migrations run on startup. |

## `audit`, `operational_log` and `credential_store`

Retention for the two log streams and the sealed-credential store. Every key
is optional.

| Key | Default | Meaning |
|---|---|---|
| `audit.retention_days` | `90` | Audit rows older than this are deleted. |
| `audit.sweep_interval_seconds` | `3600` | How often the audit sweeper runs. |
| `audit.jsonl_path` | none | Also append every audit row to this JSON Lines file. |
| `audit.jsonl_max_bytes` | `104857600` (100 MiB) | Rotate the JSON Lines file at this size. |
| `audit.jsonl_keep_files` | `14` | Rotated JSON Lines files to keep. |
| `operational_log.retention_days` | `30` | Operational-log rows older than this are deleted. |
| `operational_log.sweep_interval_seconds` | `3600` | How often that sweeper runs. |
| `credential_store.tombstone_retention_days` | `7` | Days a retired sealed credential is kept before deletion. |
| `credential_store.orphan_grace_seconds` | `3600` | Age a sealed credential must reach before it can be retired as unreferenced. Values below 60 are raised to 60. |
| `credential_store.sweep_interval_seconds` | `3600` | How often the credential-store sweeper runs. It runs only when `LOCKSMITH_CREDENTIAL_SEALING_KEY` is set. |

See [audit and monitor](../guide/07-audit-and-monitor.md).

## Egress: `egress_proxy` and `egress`

These decide how routes registered with `egress: proxied` leave the host.
Routes with `egress: direct` always connect directly.

| Key | Meaning |
|---|---|
| `egress_proxy` | HTTP CONNECT proxy URL for proxied routes. It must parse as a proxy URL. |
| `egress.mode` | `pipelock`: send proxied routes through `egress_proxy`, which is then required. `external`: connect directly and rely on your network to enforce egress. |

With `egress_proxy` set and no `egress` block, the mode is `pipelock`. With
neither set, proxied routes fail with 503 `egress_proxy_unconfigured`; they
never fall back to a direct connection. See
[egress and inspection](../concepts/egress-and-inspection.md).

## `tls`

| Key | Meaning |
|---|---|
| `upstream_ca_bundle` | PEM bundle added to the built-in roots for verifying HTTPS upstreams, such as services behind an internal CA. It adds trust; nothing turns verification off. |

## `inspection`

Content inspection for named routes.

| Key | Default | Meaning |
|---|---|---|
| `routes[].route` | required | A registration name (or a legacy `tools` name). Each route may appear once. |
| `routes[].request`, `routes[].response` | none | The policy for that direction. Leave one out to skip it. |
| `…scanners` | required | `dlp`, `injection`, `literal:<text>` (an exact string) or `sidecar:<name>`. An unknown scanner stops startup. |
| `…on_hit` | request `block`, response `flag` | `pass`, `flag`, `redact` or `block`. A direction whose scanners are only `injection` or sidecars defaults to `flag`. |
| `…on_error` | request `fail_closed`; response `fail_open`, or `fail_closed` when `on_hit` is `redact` or `block` | What happens when a body can't be scanned (a scanner error, or a compressed, oversized or NDJSON body). |
| `…max_scan_bytes` | `1048576` | Bytes scanned per body. |
| `sidecars[].name` | required | Unique; lowercase letters, digits, `-` and `_`. Used as `sidecar:<name>`. |
| `sidecars[].socket` | required | Absolute path of the sidecar's Unix socket. |
| `sidecars[].timeout_ms` | `1000` | Per-scan timeout; at least 1. |

See [egress and inspection](../concepts/egress-and-inspection.md).

## `mcp`

Limits and trust for native MCP connections on `/mcp/`. Each limit can be
lowered but not raised: zero, or a value above the default, stops startup.

| Key | Default | Meaning |
|---|---|---|
| `upstream_ca_bundle` | none | Extra CA bundle for native MCP upstreams. |
| `allowed_hosts` | `localhost`, `127.0.0.1`, `[::1]` | `Host` values accepted on `/mcp/`; 1 to 16 entries. Use the listener's real authority. |
| `allowed_origins` | `[]` | Exact browser origins accepted; up to 16. A request without `Origin` is allowed; an empty list refuses any request that sends one. |
| `ingress` | `128` | Concurrent HTTP operations on `/mcp/`, including time spent waiting on authentication, the database and the body. |
| `sessions` | `256` | Sessions in the process, counting those starting up and closing. |
| `sessions_per_agent` | `16` | Open sessions per agent. |
| `sessions_per_connection` | `16` | Open sessions per agent and connection. |
| `messages` | `256` | Queued SDK messages, and separately remembered request IDs, per session. |
| `streams` | `4` | Request-response streams per session, plus one long-lived GET. |
| `handshake_ms` | `5000` | Time allowed for session setup. |
| `lifetime_ms` | `900000` | Longest a session may live, counted from allocation. |
| `idle_ms` | `300000` | Idle time before a session closes. |
| `request_ms` | `10000` | Time for one request through authentication, input and dispatch. |
| `response_ms` | `60000` | Time for one response or GET stream; activity does not reset it. |
| `request_bytes` | `262144` | Largest request body. |

See [native MCP](../operator/native-mcp.md).

## `oauth_consent`

Operator-approved OAuth accounts. Requires `listen.admin_socket` and
`LOCKSMITH_OAUTH_SEALING_KEY`; the daemon refuses to start without either.

```yaml
oauth_consent:
  callback:
    address: "127.0.0.1:9443"
    cert_path: "/etc/locksmith/tls/callback.crt"
    key_path: "/etc/locksmith/tls/callback.key"
  profiles:
    - id: linear
      kind: controlled-linear-v1
      # ...fields for this kind; see the pages below
```

| Key | Meaning |
|---|---|
| `callback.address` | Loopback address (`127.0.0.1` or `::1`, non-zero port) of the HTTPS callback listener. |
| `callback.cert_path`, `callback.key_path` | Certificate and key for the callback listener. |
| `profiles` | One to eight provider profiles. Each has an `id` and a `kind` that sets its other fields. |

The profile fields depend on the provider. See
[controlled consent](../operator/oauth-consent.md),
[hosted Linear](../operator/hosted-linear.md),
[Slack](../operator/slack-oauth.md) and
[declared OAuth services](../operator/custom-oauth.md).

## `logging` and `shutdown`

| Key | Default | Meaning |
|---|---|---|
| `logging.level` | `info` | Log level. `RUST_LOG`, when set, takes precedence. |
| `logging.file` | none | Write logs to this file instead of stdout. If it cannot be opened, the daemon does not start. |
| `shutdown.drain_window_seconds` | `30` | How long in-flight requests get to finish after SIGTERM. |

## Legacy mode

Without `listen.admin_socket` and with `listen.auth_mode: bearer`, Locksmith
runs without per-agent identity or an admin API. Only `tools` entries
**without** `auth` are served. An entry with `auth` is refused: requests get
401 `agent_identity_required` and `/readyz` returns 503, because a shared
token cannot select an account. To use credentials, set the admin socket,
register agents and select their accounts.

`inbound_auth` gates the entries that are served:

| Key | Meaning |
|---|---|
| `inbound_auth.mode` | `bearer` checks every request for `inbound_auth.token`. |
| `inbound_auth.token` | The single token every agent presents. |

> **Warning.** In legacy mode, if `inbound_auth` is absent, its `mode` is not
> `bearer`, or it has no `token`, the served entries are open to anyone who
> can reach the listener. Keep the listener on loopback, or set the admin
> socket.

Once `listen.admin_socket` is set, `inbound_auth` is ignored (with a warning
if a token is set) and each agent uses its own token or certificate.

### `tools`

```yaml
tools:
  - name: search
    description: "Web search"
    upstream: "https://api.search.example.com"
    egress: proxied              # direct (default) | proxied
    auth:
      header: "Authorization"
      value: { from_env: { var: SEARCH_TOKEN } }
    timeouts:
      request_seconds: 30
      idle_seconds: 60
    body_limit_bytes: 10485760
    response:
      max_size_bytes: 1048576
      content_type_allowlist: ["application/json"]
      redaction_patterns:
        - id: api_key
          regex: "sk-[A-Za-z0-9]{20,}"
          replacement: "[REDACTED:api_key]"
```

| Key | Default | Meaning |
|---|---|---|
| `name`, `description`, `upstream` | required | The route name (`/api/<name>/`), a description and the upstream base URL. |
| `egress` | `direct` | `direct` or `proxied`; see [egress](#egress-egress_proxy-and-egress). |
| `auth.header`, `auth.value` | none | Header and credential to copy into the database. Only `{from_env: {var: VAR}}` is copied, and the variable must hold the whole header value (for example `Bearer <token>`); a `prefix` is not carried over. Text such as `"Bearer ${VAR}"` is expanded when the file is read, so it is not copied. |
| `timeouts.request_seconds` | `30` | Total time for one upstream request. |
| `timeouts.idle_seconds` | `60` | Longest gap between reads. |
| `body_limit_bytes` | `10485760` | Largest request body. |
| `response.max_size_bytes` | none | Largest upstream response. |
| `response.content_type_allowlist` | none | Accepted response content types. |
| `response.redaction_patterns` | `[]` | `id`, `regex` and optional `replacement` (default `[REDACTED:<id>]`) for each pattern. |

The `response` controls are described in the
[response controls runbook](../operator/runbooks/response-controls.md).

The `auth` keys matter only for the copy into the database. With the admin
socket set, `tools` entries are copied into the database at
startup, but only names the database does not already have; later edits to
an entry are ignored. Only environment-variable credentials are copied.
An entry whose `auth.value` is anything else (text, `from_file_sealed` or
another backend) is skipped and not served. Backends log a warning for the
entry; text is counted only in the startup summary. Register services with
the CLI instead.

### Deprecated keys

These are translated or dropped, with a warning at startup:

| Key | What happens |
|---|---|
| `telemetry` | Removed; ignored. |
| `tools[].cloud` | Translated to `egress`. |
| `tools[].timeout_seconds` | Translated to `timeouts.request_seconds`. |

## Environment variables

| Variable | Read by | Meaning |
|---|---|---|
| `LOCKSMITH_CREDENTIAL_SEALING_KEY` | daemon | Key for credentials stored in Locksmith. Without it, stored credentials cannot be set or used. |
| `LOCKSMITH_OAUTH_SEALING_KEY` | daemon | Key for OAuth sessions. Without it the OAuth admin routes are not mounted and OAuth routes cannot be used; `oauth_consent` then stops startup. |
| `LOCKSMITH_SEED_PATH` | daemon | Seed catalog to load. Default `/etc/locksmith/seed/catalog.yaml`; empty skips seeding. |
| `RUST_LOG` | daemon | Overrides `logging.level`. |
| `OP_*` | daemon | Passed to the 1Password `op` CLI that resolves `op_*` credentials, for example `OP_SERVICE_ACCOUNT_TOKEN`. |
| `LOCKSMITH_SOCKET` | CLI | Admin socket path; default `/var/run/locksmith/admin.sock`. |
| `LOCKSMITH_ADMIN_URL`, `LOCKSMITH_CA_BUNDLE` | CLI | Admin HTTPS URL and the CA bundle that verifies it. |
| `LOCKSMITH_OP_TOKEN` | CLI | Operator token. |
| `LOCKSMITH_AGENT_TOKEN` | CLI | Agent token, for agent self-service commands. |

A sealing key that is set but malformed stops startup.

Services can also read their credentials from environment variables named in
their registration; see [credential custody](../guide/03-credential-custody.md).
