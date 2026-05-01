# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Working branch

`develop` is the default working branch — it carries M0..M7 plus post-v1.0.0 enhancements (currently tagged **v1.1.0**). `main` only contains M0. Cut feature branches from `develop`.

The cold-start handoff is `docs/v2/HANDOFF.md`. Read it before substantive work — it tracks per-task status, gates, and post-v2 backlog. Authoritative spec: `docs/v2/SPEC.md` (with `SPEC.state.md` for "what's actually in code"). PRD/threat-model/runbooks live under `docs/v2/`.

**Ignore the top-level `SPEC.md`.** It's the deprecated M0-era "Secure Agent Proxy (SAP)" document — the project was renamed to agent-locksmith and v2 explicitly removed the `/llm/*`, `/mcp/*`, `/a2a/*` namespaces and the wire-level scanner sidecar described there (see PRD D-11/D-15/D-17/D-18). It's kept only for archaeology and carries a deprecation banner at the top.

## Common commands

```bash
# Build (release)
cargo build --release           # binaries: target/release/{locksmithd,locksmith}

# Tests + lint (CI runs all three; clippy is -D warnings)
cargo test --all
cargo clippy --all-targets -- -D warnings
cargo fmt --check

# Single test binary / single test
cargo test --test admin_https_mtls_e2e_test
cargo test --test proxy_test -- streaming_passthrough  # name filter
cargo test path::to::module::test_name                 # for unit tests in src/

# Audit-write benchmark (criterion)
cargo bench --bench audit_write_bench

# Run daemon against the example config (tools degrade unless env vars are set)
GITHUB_TOKEN=... ANTHROPIC_API_KEY=... TAVILY_API_KEY=... \
  target/release/locksmithd --config config.example.yaml

# Operator CLI — UDS by default, HTTPS via --admin-url / LOCKSMITH_ADMIN_URL
target/release/locksmith agent list
LOCKSMITH_ADMIN_URL=https://host:9201 LOCKSMITH_CA_BUNDLE=ca.crt \
  target/release/locksmith agent list
```

SQLite migrations under `migrations/` are embedded and applied on daemon startup via `migrations::open_and_migrate`; there is no external migration tool to run.

## Two-binary layout

`Cargo.toml` declares two binaries from one crate:

- **`locksmithd`** (`src/main.rs`) — the daemon. Loads YAML config, wires telemetry + shutdown coordinator, calls `daemon::run`.
- **`locksmith`** (`src/cli/main.rs`) — operator + agent self-service CLI. Talks to the daemon over the admin UDS or admin HTTPS. Subcommands: `agent`, `bootstrap`, `tool`, `audit`, `export`, `mtls`, `status`, `rotate`. Exit codes are SPEC §4.7.2 (0/1/2/3/4/5).

Library code (everything in `src/lib.rs`) is shared between both binaries and the integration tests in `tests/` (53 test binaries, ~250 tests at v1.1.0).

## Runtime architecture

`daemon::run` (in `src/daemon.rs`) is the single composition root. Everything below is wired from there:

1. **Shared config** — `Arc<ArcSwap<AppConfig>>`. The agent router and the AdminService both observe the same snapshot, so hot reload (T1.5) is unified across surfaces. The `deny_unknown_fields` schema is in `src/config.rs`.
2. **Credential resolution** — `secret::SecretResolver` resolves each `tool.auth.value: SecretRef` at startup into an `Arc<ArcSwap<ResolvedCreds>>`. Backends in `src/secret/`: `EnvBackend` (incl. legacy `${VAR}` strings), `FileSealedBackend` (systemd-creds-decrypted files; rejects group/world-readable), Vault + AWS stubs. Tools whose secrets fail to resolve are inactive (degraded per INF-4) but the daemon still boots.
3. **Admin substrate** (built only when `listen.admin_socket` is set) — opens the SQLite pool (`migrations::open_and_migrate`), constructs `AgentRepository`, `BootstrapTokenRepository`, `AuditRepository`, the `BearerAuthenticator` (for agents), the `OperatorAuthenticator` (loaded from `operator_credentials_path`), and the `AdminService`. The audit repository is **shared** with the agent listener so proxy and admin writes hit the same SQLite pool and JSONL mirror.
4. **Audit retention sweeper** — bounded `DELETE WHERE ts < cutoff` on a tokio interval; co-terminates with the shutdown signal.
5. **Agent listener** — switches on `listen.auth_mode`:
   - `Bearer`: plain TCP + axum.
   - `Mtls` / `Both`: TLS-terminated TCP via `agent_listener::bind_and_serve_mtls`. The handshake verifies client certs against `listen.mtls.ca_bundle_path`; the resolved peer cert is stamped into request extensions for `auth::auth_middleware` to consume. `MtlsAuthenticator` (in `src/mtls/`) maps cert identity (CN → SAN_DNS → SAN_URI) to an agent row, applies CRL + local blocklist, and emits `auth_method=mtls` audit rows.
6. **Admin UDS listener** — at `listen.admin_socket.path`. AdminService handlers live in `src/admin/service.rs`; the UDS shim is `src/admin/uds.rs`.
7. **Admin HTTPS listener** (M4, off by default) — same `UdsState` / handlers, different transport. Supports `Bearer`, `Mtls`, or `Both` independently of the agent listener. Operator client certs map to operators via `OperatorRecord.cert_identity`.
8. **Bootstrap-only listener** (M6 / C-4) — separate single-endpoint TLS listener for agent enrollment that doesn't require operator credentials.

Both listeners share one `ShutdownCoordinator` with a configurable drain window (`shutdown.drain_window_seconds`, default 30s).

## Agent request flow (the proxy hot path)

Router is built by `app::build_app_full` in `src/app.rs`:

```
/livez, /health, /readyz, /version, /tools     unauthenticated (livez/readyz)
/api/{tool_name}/{*path}                       agent-authenticated; bearer or mtls
                                               → proxy::proxy_handler
```

`proxy::proxy_handler` (`src/proxy.rs`):

1. Reads `auth_method` + `agent_public_id` from request extensions stamped by `auth::auth_middleware`.
2. Resolves the tool from the active set (`config.active_tools_against(&resolved_creds)` — tools without resolved credentials are filtered out, which is also why they vanish from `/tools` and cause `/readyz` to 503).
3. Strips agent-sent `Authorization` and `x-api-key` headers, plus the tool's configured auth header (defense against agent override).
4. Injects credentials from `resolved_creds` into the upstream request.
5. Routes through `egress_proxy` (CONNECT proxy / Pipelock) when `tool.egress: proxied` (or legacy `cloud: true`); otherwise direct.
6. Applies `ResponseControls` (M7) when the tool has a `response:` block: `max_size_bytes` (with streaming truncation marker via `SizeCappedStream`), `content_type_allowlist`, `redaction_patterns` (regex; cleartext is **never** logged — audit stores `pattern_id`, match count, and SHA-256 hash).
7. Emits one `AuditEvent` per request to `AuditRepository`, which fans out to SQLite + the optional JSONL sink.

`/readyz` is the source-of-truth liveness check for orchestrators: it returns 503 if any tool with an `auth` block has no resolved credential. `/livez` is liveness only. `/health` is an M0 alias for `/livez`.

## Module map

```
src/
  main.rs                  locksmithd entry
  lib.rs                   public module surface
  daemon.rs                composition root (read this first)
  app.rs                   axum router + AppState
  proxy.rs                 hot path: header strip, credential inject, egress, response controls
  auth.rs                  agent-auth middleware (bearer + mtls dispatch, stamps extensions)
  auth_v2/                 BearerAuthenticator (agents) + OperatorAuthenticator (operators)
  mtls/                    MtlsValidator (webpki) + CrlStore + Blocklist + MtlsAuthenticator
  admin/                   AdminService (handlers) + uds + https + bootstrap_listener + uds_client
  agent_listener.rs        TLS-terminated TCP serve loop for auth_mode=mtls/both
  repo/                    AgentRepository, BootstrapTokenRepository, AuditRepository (sqlx)
  audit_sink.rs            JsonlSink (size-rotating mirror)
  secret/                  SecretRef + SecretResolver + Env / FileSealed / Vault / AWS backends
  response_controls.rs     M7: size cap, content-type allowlist, regex redaction
  config.rs                deny_unknown_fields YAML schema (ListenConfig, ToolConfig, AuditConfig, …)
  migrations.rs            embeds migrations/*.sql; open_and_migrate(path) → SqlitePool
  client_pool.rs           reqwest client cache keyed by egress mode + timeouts
  cli/                     locksmith CLI: client.rs (UDS/HTTPS), commands/{agent,audit,bootstrap,export,mtls,self_svc,tool}.rs
  shutdown.rs              ShutdownCoordinator + drain window
  telemetry.rs             tracing-subscriber JSON setup
  deprecation.rs           one-shot warnings for legacy config shapes
tests/                     integration tests, one binary per file
benches/audit_write_bench  criterion bench — validates A-2 / INF-26 audit throughput
migrations/                SQLite schema (embedded into the binary)
dist/systemd/              hardened unit template (NoNewPrivileges, ProtectSystem=strict, …)
dist/examples/             smallstep mTLS + sealed-secrets worked examples
docs/v2/                   SPEC, PRD, HANDOFF, threat-model, runbooks
```

## Conventions worth knowing

- **Secrets discipline.** Anything secret rides in `secrecy::SecretString` (zeroized on drop). It must never appear in log fields, error messages, HTTP responses, audit rows, or test fixtures committed to the repo. The redaction subsystem hashes cleartext into audit, never the cleartext itself.
- **`deny_unknown_fields`** is on every config struct. Adding a field means a schema change — bump tests in `tests/config_*` and the example config alongside.
- **Hot-reload carve-out.** Listener-shape config (admin_https paths, mTLS cert paths, bind ports) requires a daemon restart by design; tools/audit/retention/response_controls are reload-safe via the shared `ArcSwap<AppConfig>`. T2.20 (extending hot reload to remaining non-listener fields) is on the post-v2 backlog.
- **Auth surfaces are independent.** Agent listener (`listen.auth_mode`) and admin HTTPS (`listen.admin_https.auth_mode`) each pick `bearer | mtls | both` separately. The UDS admin listener uses operator bearer tokens only (peer-uid gate is the OS).
- **Audit is one schema, two sinks.** Every event goes through `AuditRepository::record`, which writes to SQLite and optionally appends to a size-rotating JSONL mirror. New event types extend `EventClass` / `event` strings — keep them stable; runbooks and CLI queries grep against them.
- **Cloud routing.** Tools mark `egress: proxied` (preferred) or legacy `cloud: true` to route through `egress_proxy` (typically Pipelock). LAN tools use `egress: direct` and bypass the CONNECT proxy.
- **Comments.** Existing source comments often cite SPEC tasks (`T6.5`, `INF-3`, `D-10`, `R-N6`, etc.) — those tags map to `docs/v2/SPEC.md` / `PRD.md`. Preserve that vocabulary when adding new code so future archaeology stays cheap.

## Stack-root context

The parent `agents-stack/AGENTS.md` and `agents-stack/CLAUDE.md` apply at the meta-repo level (cross-repo orchestration, `stack.py`). Implementation work belongs in this sub-repo; this CLAUDE.md takes precedence over the stack root for everything inside `agent-locksmith/`.
