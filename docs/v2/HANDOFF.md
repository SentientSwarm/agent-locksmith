# Handoff — Agent Locksmith v2 Implementation

**Last updated:** 2026-04-29
**Last session ended at commit:** `c2b7fc0` on branch `m2/implementation` (merged to `develop`)
**Default working branch:** `develop`

---

## 1. Where we are

### Branches

| Branch | State | What's there |
|--------|-------|--------------|
| `main` | Stable | M0 implementation. CI passes. |
| `develop` | M2 complete, integrated | M0 + M1 + M2 merged. The M2 acceptance contract — *"all UC-1..UC-5 demonstrable via the `locksmith` CLI against a running daemon"* — is closed. Default working branch for M3+. |
| `m2/implementation` | Merged | Kept for archaeology; no further commits. |

### What's merged into `develop` so far

- v2 PRD + design (Phases 1–7 of `software-design` skill).
- **M1** (T1.1–T1.13): inference-ready hardening. Streaming SSE passthrough, per-tool timeouts/body limits, `cloud:` → `egress:` rename via the deprecation registry, per-tool reqwest client pool, SIGTERM + drain, `/livez`/`/readyz`/`/version` split, structured token type, full local + cloud inference matrix, M1 acceptance runbook.
- **M2** (T2.1–T2.10, T2.12–T2.16, T2.22–T2.27): agent identity + admin substrate.
  - sqlx + `migrations/0001_init.sql` + `MigrationRunner` (T2.1–T2.4)
  - `AgentRepository` + `BootstrapTokenRepository` + `AuditRepository` scaffold (T2.5–T2.7)
  - argon2 token hashing helpers (T2.8)
  - `BearerAuthenticator` + `OperatorAuthenticator` (T2.9, T2.10)
  - `AdminService` + admin UDS listener + middleware + agent + operator handlers (T2.12–T2.16)
  - `daemon::run` runtime + `locksmithd` binary + `locksmith` CLI (T2.22–T2.27)

### Test + lint state at M2 closure

- `cargo test --tests`: **126 / 126 pass** across 23 test binaries.
- `cargo clippy --all-targets -- -D warnings`: **clean**.
- `cargo fmt --check`: **clean**.

### Verification gates closed during M2

| Task | Gate | Status |
|------|------|--------|
| T2.4 | Schema review | Closed; `migrations/0001_init.sql` matches SPEC §4.6.2 verbatim |
| T2.9 | AgentAuthenticator | Closed; constant-time + decoy-on-miss verified |
| T2.12 | AdminService | Closed; cross-transport + cross-namespace rejection verified |

---

## 2. M2 acceptance demo

```bash
cargo build --release

# Operator setup: hash an operator token into operators.yaml.
# (One-time bootstrap; the long form is documented in SPEC §4.7.5.)

# Run the daemon.
./target/release/locksmithd --config /etc/locksmith/config.yaml &

# Operator workflow (cleartext token in the password manager).
export LOCKSMITH_OP_TOKEN=lkop_...
./target/release/locksmith agent register --name agent-alpha
# {"public_id":"ag_…","token":"lk_…","allowlist":null}

export LOCKSMITH_AGENT_TOKEN=lk_…
./target/release/locksmith status
# Returns the agent's snapshot.

./target/release/locksmith rotate
# Rotates the agent's token (D-13).

# Bootstrap path (UC-5).
./target/release/locksmith bootstrap mint --reusable
# {"public_id":"bt_…","token":"lkbt_…","scope":{…}}
```

This is the contract: `cargo run` + the CLI flows above demonstrate UC-1 (operator register), UC-3 (agent status), UC-4 (revoke), UC-5 (bootstrap mint → register → status).

---

## 3. What's left for M3

M3 is the audit pipeline. SPEC §6.2 T3.1..T3.10. The schema is already in place (`audit` table, indexes, CHECK constraints, EventClass + Decision enums in `repo::audit`); M3 wires writes from the proxy + admin paths, adds a JSONL sink, and lands the retention sweeper.

### High-level sequence

| Task | Summary |
|------|---------|
| T3.1 | AuditWriter on the proxy hot path: every proxied request emits one row (success or denial) keyed by agent + tool. |
| T3.2 | AuditWriter on the admin path: every register/revoke/rotate/bootstrap_mint/bootstrap_revoke emits an "operator" event row. |
| T3.3 | Optional JSONL sink with daily rotation + 100MB cap (Q-6). Mirrors the SQLite columns 1:1 (PRD §14.1 #6). |
| T3.4 | INF-13 audit-on-failure: failed authentications and denied tool-allowlist checks emit `auth_failure` / `policy_denial` rows. |
| T3.5 | Retention sweeper: 90-day time-based delete (Q-26 option C). Runs as a daemon-internal task on a configurable cadence. |
| T3.6 | `locksmith audit query` CLI subcommand: filter by agent / tool / event_class / decision / time-range; --format table/json/yaml. |
| T3.7 | Backpressure under audit failure (Q-28): synchronous default; if the disk is full or the writer panics, the proxy fails closed. |
| T3.8 | INF-26 throughput verification: the audit-write hot path sustains ≥ 1000 writes/sec on commodity SSD. Failing this assumption triggers the async-writer carve-out. |
| T3.9 | Bench scaffold: `locksmith bench audit-write` (parallel writers, measured throughput + p50/p99). |
| T3.10 | M3 acceptance runbook: queryable by operator + retention sweeper observable. |

### Known follow-ups carried into M3

| Finding | Origin | Disposition |
|---------|--------|-------------|
| `last_used_at` is best-effort | M2 BearerAuthenticator | Document in operator runbook; M3 makes the audit write authoritative. |
| Operator scope is reserved but not enforced | All operator handlers | D-6 reserved; v1 operator credentials are all-or-nothing. |
| INF-13 audit-on-failure not wired | M2 authenticators + AdminService | T3.4 lands this. |

### Deferred from M2 (do not block M3)

| Task | Issue | Reason |
|------|-------|--------|
| T2.11 RateLimiter | #24 | Defensive; not blocking UC demonstrability. |
| T2.17 typed `SecretRef` | unfiled | Schema evolution. Field-scoped `${VAR}` already works. |
| T2.18..T2.21 (config polish, hot reload, startup checks) | unfiled | M2.x cleanup. |
| T2.28..T2.29 bench subcommands | unfiled | A-1 verification; M3 uses these for INF-26. |

---

## 4. Conventions and gotchas

These came from M0/M1/M2 implementation and apply forward.

### Token wire format

- **Agent**: `lk_<22-char-base64-id>.<43-char-base64-secret>`
- **Operator**: `lkop_<id>.<secret>`
- **Bootstrap**: `lkbt_<id>.<secret>`

**Single-underscore separator only.** SPEC §4.2.8 reflects this.

### Two binaries

- `locksmithd` — the daemon (`src/main.rs`). Reads YAML config; binds the agent TCP listener and (when configured) the admin UDS.
- `locksmith` — the operator + agent CLI (`src/cli/main.rs`). Talks to a running daemon over its admin UDS.

The admin UDS is opt-in: a config without `listen.admin_socket` runs `locksmithd` with TCP only (M0/M1 behavior).

### Daemon runtime structure

`src/daemon.rs::run` is the canonical entry point. It validates the admin substrate triple (`listen.admin_socket` + `database.path` + `operator_credentials_path`), opens SQLite, builds the AdminService, and spawns both listeners against a shared `ShutdownCoordinator`. Drain time is bounded by `shutdown.drain_window_seconds` (default 30s).

`AppState.config` is `Arc<ArcSwap<AppConfig>>`. The agent listener and the AdminService both observe this single snapshot — hot reload (T1.5) extends to admin without further plumbing.

### UDS HTTP client (`src/admin/uds_client.rs`)

A minimal hyper 1.x http1 client over `tokio::net::UnixStream`. No hyperlocal dep; no pool. Each request opens a fresh connection. This is fine for an interactive CLI talking to a local daemon; if M4 ever needs a long-lived UDS client (it won't — M4 is HTTPS) we'll reach for `hyper-util::Client`.

### CLI exit codes (§4.7.2)

`0` ok | `1` generic | `2` usage | `3` auth | `4` not-found | `5` conflict.

`CliError::exit_code()` is the single mapping point. Adding a new error variant means updating that match. The cli_e2e tests pin the contract for the auth code.

### Deprecation registry (INF-24)

`src/deprecation.rs` is the single mechanism for renamed/removed fields. Currently registered:

- `tools[].cloud` → `tools[].egress` (M1)
- `telemetry` → removed (M1; was M0 dead code)
- `tools[].timeout_seconds` → `tools[].timeouts.request_seconds` (M1)

### YAML config parsing pipeline

`config::parse_config_str` is the canonical entry. The pipeline:
1. `expand_env_vars` (textual `${VAR}` → env value)
2. Untyped `serde_yaml::Value` parse
3. `apply_deprecations` (in-place tree edits per registry)
4. Typed `serde_yaml::from_value::<AppConfig>` with `deny_unknown_fields`

Tests must use `parse_config_str`, not `serde_yaml::from_str` directly.

### SQLite migrations

- Migration files cannot contain `PRAGMA synchronous` or `PRAGMA journal_mode` — sqlx wraps each migration in a transaction. They're applied at connection-open via `SqliteConnectOptions` + the `after_connect` hook (`wal_autocheckpoint = 1000`).
- Forward-only per INF-11. Rollback = backup + restore.

### argon2 parameters

`m=4096 KiB (4 MiB), t=3, p=1` (Q-13). ~5ms verify on commodity hardware.

### Decoy-on-miss in authenticators

Both `BearerAuthenticator` and `OperatorAuthenticator` precompute a stored decoy hash. On any "this credential isn't valid" path they still run an argon2 verify against the decoy so the timing channel is closed. **Don't optimize this away** — it's a security property that gate review verified.

### Test infrastructure

- **`wiremock`** for fixture upstreams in proxy tests.
- **`tempfile`** for ephemeral SQLite + sockets.
- **`axum_test::TestServer::new(router)`** (no `.unwrap()` in v19).
- **No mocks for repositories** — repo + admin tests run against real (in-memory or temp-file) SQLite.
- **`cli_e2e_test`** spawns `locksmithd` as a child process and drives `locksmith` via `Command`. Each subcommand exits cleanly; auth/conflict/not-found exit codes are pinned.

### Cloud provider tests

`tests/inference_matrix_cloud_test.rs` is local-only per Q-2. CI never runs it; engineers run pre-PR with `ANTHROPIC_API_KEY` and `OPENAI_API_KEY` set.

### CI mismatch with local toolchain

Local Rust 1.88+ has stricter `clippy` defaults than the CI's `dtolnay/rust-toolchain@stable`. Always run `cargo clippy --all-targets -- -D warnings` locally before commit.

---

## 5. Where to look

| Need | Read |
|------|------|
| Why we're building this | `docs/v2/PRD.md` |
| How we're building it | `docs/v2/SPEC.md` |
| What the schema looks like and why | SPEC §4.6.2 (DDL) + §4.2.10/§4.2.11/§4.2.12 (repos) |
| Operator-facing UX | SPEC §4.7 — sample CLI invocations, YAML configs, error envelopes |
| Implementation plan | SPEC §6.2 — canonical task list |
| Verification policy | SPEC §6.4.1 |
| What was decided and why | SPEC §15 (D-1..D-18) + §2 (28 resolved questions) |
| Inferred design requirements | SPEC Appendix B.4 — INF-1..INF-26 |
| Deployment-time assumptions | SPEC §2.1 — A-1..A-4 |
| M1 acceptance procedure | `docs/v2/runbooks/m1-inference-hardening.md` |

---

## 6. Resuming for M3

```bash
git fetch
git checkout develop
git pull

cargo test --tests
cargo clippy --all-targets -- -D warnings
cargo fmt --check

# Branch off develop for M3.
git checkout -b m3/audit-pipeline
```

Work flow that has held through M1 and M2:

- TDD per task (`superpowers:test-driven-development`): failing test first, implement to green.
- Verification gates at T3.5 (retention correctness) and M3 closure. Self-review or `devloop:local-review` before merge.
- Conventional commits with the milestone in the subject and `Closes #N` in the body.
- Issues created proactively for each §6.2 task. Apply labels: `milestone:M3`, `component:*`, `layer:*`, `kind:*`, `risk:*`, plus per-requirement labels.
- No PRs required — direct merge to `develop`. Manually `gh issue close` since auto-close only fires on merges to default branch.

---

## 7. Workflow policies (don't drift)

- **TDD per task.** Every M2 commit shipped tests-first.
- **Verification gates.** T6.2/T6.5 (MtlsValidator + MtlsAuthenticator), T6.7 (operator mTLS), and M3 retention need self-review before merge.
- **No PRs required** for this project — direct merge to `develop` is the standing instruction.
- **Schema/auth/admin gates** require self-review before merge (per §6.4.2). M2 closed three (T2.4, T2.9, T2.12).
- **GITHUB_TOKEN env var quirk:** the keyring auth for `gh` is overridden by stale `GITHUB_TOKEN`. Always invoke as `env -u GITHUB_TOKEN gh ...`.

---

*End of handoff. Push back on anything in this document that turns out wrong; update it as you go so the next handoff is accurate.*
