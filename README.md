# agent-locksmith

A Rust credential proxy that sits between AI agents and external services.
Agents never see provider API keys — locksmith injects credentials, enforces
per-agent ACLs, audits every request, and routes outbound traffic through a
configurable egress chain.

The keystone component of the [layer8-proxy][layer8] stack.

[layer8]: https://github.com/SentientSwarm/layer8-proxy

**Current version: v2.0.0** ([release notes](https://github.com/SentientSwarm/agent-locksmith/releases/tag/v2.0.0))

## What it does

- **Agent sends:** `POST /api/anthropic/v1/messages` with the agent's per-agent
  bearer token (no provider API key).
- **Locksmith validates:** the bearer is registered + the agent's ACL allows
  `anthropic`.
- **Locksmith forwards:** `POST https://api.anthropic.com/v1/messages` with
  `x-api-key: <real provider key>` injected from sealed-at-rest creds.
- **Locksmith audits:** one row per request — agent identity, tool, status,
  latency, auth_mode.

The agent discovers available tools via `GET /tools` (kind=tool) and
`GET /models` (kind=model). Discovery is per-agent ACL-filtered. Internal
middleware (`kind=infra`) is operator-only.

## Highlights (v2.0.0)

- **Kind-discriminated registrations** — `model` / `tool` / `infra` taxonomy.
  Agents reason about LLMs vs service tools differently; operator-only
  middleware (lf-scan today) lives in its own kind.
- **Per-agent bearer + ACL** — each agent registration carries an
  `allowlist` / `denylist`. The proxy hot path enforces it before reaching
  upstream.
- **mTLS feature flag** — listener `auth_mode: bearer | mtls | both`.
  Admin HTTPS path gets the same treatment.
- **OAuth credential variant** — `AuthSpec::OauthPkce` and
  `AuthSpec::OauthDeviceCode` for codex / copilot / anthropic-oauth /
  google-gemini-cli / qwen-cli. Refresh tokens sealed at rest with
  AES-GCM (`LOCKSMITH_OAUTH_SEALING_KEY`); access tokens auto-refresh.
- **Seed catalog** — 16 default providers baked into the image
  (anthropic, openai, openrouter, ai-gateway, ollama, lmstudio, tavily,
  github, duckduckgo, wikipedia, lf-scan + 5 OAuth providers). Operators
  provide `.env` credentials and override site-specific fields via the
  admin API.
- **Admin substrate** — UDS (default) and optional HTTPS for cross-host
  operations. Agent registration, tool/model PUT, audit query, OAuth
  bootstrap.
- **Audit** — every proxy request + admin write emits one structured
  audit row; SQLite + optional JSONL mirror.
- **Memory-safe secrets** — credentials in `secrecy::SecretString`
  (zeroized on drop); never logged, never in HTTP responses.

## Two-binary layout

```
locksmithd   the daemon (src/main.rs)
locksmith    operator + agent self-service CLI (src/cli/main.rs)
```

CLI subcommands: `agent` (operator), `tool` / `model` / `infra` (operator —
catalog management), `oauth` (operator — OAuth session bootstrap), `audit`,
`bootstrap` (token mint), `mtls`, `status` / `rotate` (agent self-service).

## Quick start

### Build

```bash
cargo build --release
# binaries: target/release/{locksmithd,locksmith}
```

### Configure

```yaml
# /etc/locksmith/config.yaml
listen:
  host: "127.0.0.1"
  port: 9200
  auth_mode: bearer       # bearer | mtls | both
  admin_socket:
    path: "/var/run/locksmith/admin.sock"

operator_credentials_path: "/etc/locksmith/operators.yaml"

database:
  path: "/var/lib/locksmith/locksmith.db"

audit:
  retention_days: 90
  sweep_interval_seconds: 3600

# Optional egress chokepoint (typically Pipelock CONNECT proxy).
egress_proxy: "http://127.0.0.1:8888"
```

The seed catalog at `/etc/locksmith/seed/catalog.yaml` (baked into the
docker image) populates the registrations table on first boot. Operators
provide credentials via env vars (or the layer8-proxy-site sealed-creds
flow); no per-tool YAML required for the 16 default providers.

### Run

```bash
# Daemon — reads config, opens UDS, binds agent listener.
target/release/locksmithd --config /etc/locksmith/config.yaml

# Operator CLI (UDS by default).
LOCKSMITH_OP_TOKEN=lkop_... \
  target/release/locksmith model list
LOCKSMITH_OP_TOKEN=lkop_... \
  target/release/locksmith agent register \
    --name hermes-mini-m1 --allowlist anthropic,openai,tavily

# Agent self-service.
LOCKSMITH_AGENT_TOKEN=lk_... \
  target/release/locksmith status
```

For the Docker Compose / production deployment story, see
[layer8-proxy][layer8] and the per-host site repos
(`layer8-proxy-site`, `hermes-site`, `openclaw-site`).

## Wire surface

### Public (per-agent-bearer authenticated; ACL-filtered)

```
GET  /livez                      unauthenticated; liveness probe
GET  /readyz                     unauthenticated; readiness (503 if any
                                 tool with auth has no resolved credential)
GET  /version                    unauthenticated
GET  /skill                      auth-optional; markdown personalised when
                                 a valid agent bearer is supplied
GET  /tools                      kind=tool catalog, ACL-filtered
GET  /models                     kind=model catalog, ACL-filtered
ANY  /api/{tool_name}/{*path}    proxy hot path
```

### Operator (operator-credential authenticated; UDS or HTTPS)

```
GET    /admin/operator/agents
POST   /admin/operator/agents                    register an agent
GET    /admin/operator/agents/{public_id}
PATCH  /admin/operator/agents/{public_id}        modify ACL
POST   /admin/operator/agents/{public_id}/revoke

GET    /admin/operator/{tools,models,infra}
GET    /admin/operator/{tools,models,infra}/{name}
PUT    /admin/operator/{tools,models,infra}/{name}
DELETE /admin/operator/{tools,models,infra}/{name}
POST   /admin/operator/{tools,models,infra}/{name}/enable

POST   /admin/operator/oauth/{name}/bootstrap    OAuth session (Phase F)
GET    /admin/operator/oauth/{name}              session status
DELETE /admin/operator/oauth/{name}              revoke

GET    /admin/operator/bootstrap_tokens
POST   /admin/operator/bootstrap_tokens
POST   /admin/operator/bootstrap_tokens/{public_id}/revoke

GET    /admin/operator/audit                     audit query
```

### Error envelope (§4.7.9)

Every error renders as:

```json
{ "error": { "type": "...", "code": "...", "message": "..." } }
```

Codes include `name_in_use`, `reserved_name`, `auth_required`,
`wrong_kind`, `model_auth_required`, `tool_not_allowed`,
`invalid_credential`, `oauth_session_missing`, `oauth_refresh_failed`,
`oauth_sealing_key_unset`, etc. The agent-facing surface follows
existence-leak avoidance (Q-8): admin errors never reveal whether a
name exists; per-agent errors are generic.

## Configuration reference

```yaml
listen:
  host: "127.0.0.1"
  port: 9200
  auth_mode: bearer | mtls | both
  admin_socket:
    path: "/var/run/locksmith/admin.sock"
  admin_https:                # optional; v2.0.0+
    bind_address: "0.0.0.0:9201"
    auth_mode: bearer | mtls | both
    cert_path: "..."
    key_path: "..."
  mtls:                       # required when auth_mode != bearer
    ca_bundle_path: "..."
    server_cert_path: "..."
    server_key_path: "..."

operator_credentials_path: "/etc/locksmith/operators.yaml"

database:
  path: "/var/lib/locksmith/locksmith.db"

audit:
  retention_days: 90
  sweep_interval_seconds: 3600
  jsonl_path: "/var/log/locksmith/audit.jsonl"   # optional mirror
  jsonl_max_bytes: 104857600
  jsonl_keep_files: 7

egress_proxy: "http://127.0.0.1:8888"

logging:
  level: info

shutdown:
  drain_window_seconds: 30

# Pre-Phase-E `tools:` block is still accepted for backward compat;
# entries are migrated into the registrations table at first boot
# (legacy_bootstrap shim). Removed in v0.3. New deployments rely on
# the seed catalog + admin API instead.
tools: []
```

## Security model

- **Credential confinement**: provider API keys never leave locksmith.
  Agent processes literally don't hold them.
- **Per-agent identity**: every agent has its own bearer; revoke is
  per-agent.
- **ACL enforcement**: hot-path `tool_allowlist` / `tool_denylist`
  check before any upstream contact.
- **Audit trail**: every request → one structured row (SQLite + JSONL
  mirror). `auth_method` (bearer / mtls), `auth_mode` (none / header /
  bearer / oauth_*), `oauth_session_id` for forensic correlation.
- **Sealed creds at rest**: provider keys via `SecretRef::FromFileSealed`
  (systemd-creds / openssl-sealed); OAuth refresh tokens via AES-GCM
  with `LOCKSMITH_OAUTH_SEALING_KEY`.
- **Header stripping**: agent-sent `Authorization` / `x-api-key` are
  stripped before forwarding, defense-in-depth even when the
  registration is `auth: none`.
- **mTLS** (feature flag): client-cert authentication on the agent
  listener and admin HTTPS — independent settings.

## Deployment

```
       ┌──────────┐
agent ─┤  bearer  ├─► locksmith :9200 ──► pipelock :8888 ──► Internet
       └──────────┘         │
                            ├──► LAN services (direct egress)
                            └──► lf-scan :9100 (kind=infra middleware)
```

For the canonical deployment story:

- **Stack bundle**: [layer8-proxy][layer8] — Docker Compose composition.
- **Per-host site repo**: `layer8-proxy-site` (proxy operator) and
  `hermes-site` / `openclaw-site` (agent operator).
- **Stack docs**: `agents-stack/docs/{spec,prd,adrs,plans}/`.

## Documentation

- **Stack-level (cross-repo)**:
  - [`agents-stack/docs/spec/v0.2.0.md`][spec] — formal as-built design.
  - [`agents-stack/docs/prd/v0.2.0.md`][prd] — user-facing requirements.
  - [`agents-stack/docs/adrs/`][adrs] — cumulative decisions
    (kind taxonomy, OAuth, etc.).

- **User docs (locksmith-side)**:
  - [`docs/user/concepts/`](docs/user/concepts) — kind taxonomy, error
    envelope, agent identity + ACL, trust boundary.
  - [`docs/user/agent-integration/`](docs/user/agent-integration) —
    wiring agents (hermes, openclaw) into a layer8-proxy deployment.

- **Engineering docs (per-component)**:
  - [`docs/v2/SPEC.md`](docs/v2/SPEC.md) — engineering spec with task
    references (T1.x, T2.x, …).
  - [`docs/v2/HANDOFF.md`](docs/v2/HANDOFF.md) — cold-start handoff for
    contributors.
  - [`docs/v2/runbooks/`](docs/v2/runbooks) — operational runbooks.

[spec]: https://github.com/SentientSwarm/agents-stack/blob/main/docs/spec/v0.2.0.md
[prd]: https://github.com/SentientSwarm/agents-stack/blob/main/docs/prd/v0.2.0.md
[adrs]: https://github.com/SentientSwarm/agents-stack/blob/main/docs/adrs/

## Development

```bash
# All gates (CI runs all three; clippy is -D warnings).
cargo test --all
cargo clippy --all-targets -- -D warnings
cargo fmt --check

# Single test binary or single test.
cargo test --test admin_https_mtls_e2e_test
cargo test --test proxy_test -- streaming_passthrough

# Audit-write benchmark.
cargo bench --bench audit_write_bench

# Run daemon against the example config.
target/release/locksmithd --config config.example.yaml
```

SQLite migrations are embedded at compile time via `migrations/*.sql`
and applied by `migrations::open_and_migrate` on daemon startup. No
external migration tool to run.

## License

MIT — see [LICENSE](LICENSE).
