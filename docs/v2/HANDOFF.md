# Handoff — Agent Locksmith v2 Implementation

**Last updated:** 2026-04-29
**Last session ended at commit:** `cf65d17` on branch `m2/implementation`
**Branch is on origin:** `git fetch && git checkout m2/implementation`

This document is the cold-start context for whoever picks up next. Read it top-to-bottom before touching code; the work has accumulated nontrivial decisions and a few hard-won workarounds that aren't obvious from the diff.

---

## 1. Where we are

### Branches

| Branch | State | What's there |
|--------|-------|--------------|
| `main` | Stable | M0 implementation. CI passes. |
| `develop` | M1 complete, integrated | M1 merged via `03ed509` (no PR; merge commit on develop). Pushed. Default working branch for new milestones. |
| `m2/implementation` | M2 in progress | All M2 daemon-side spine. NOT merged to develop yet. **This is where you resume.** |

### What's merged into `develop` so far

- v2 PRD + design (Phases 1–7 of `software-design` skill).
- M1 (T1.1–T1.13): inference-ready hardening — streaming SSE passthrough, per-tool timeouts/body limits, `cloud:` → `egress:` rename via the deprecation registry, per-tool reqwest client pool, SIGTERM + drain, `/livez`/`/readyz`/`/version` split, structured token type, full local + cloud inference matrix, M1 acceptance runbook.

### What's on `m2/implementation` (5 commits ahead of develop)

| Commit | Tasks | Summary |
|--------|-------|---------|
| `3a75a5a` | T2.1 | sqlx dep |
| `6626146` | T2.2 + T2.3 | `migrations/0001_init.sql` + `MigrationRunner` |
| `c1ed127` | T2.4 | Schema review gate closed; `wal_autocheckpoint` test added; SPEC §4.6.2 clarified re PRAGMA placement |
| `469bf8a` + `db0c662` | T2.5 + T2.6 + T2.7 + T2.8 | AgentRepository, BootstrapTokenRepository, AuditRepository scaffold, argon2 helper |
| `162bee3` | T2.9 + T2.10 | `AgentAuthenticator` + bearer impl (gate), `OperatorAuthenticator`, `TokenNamespace` expansion (Operator/Bootstrap) |
| `cf65d17` | T2.12 + T2.13 + T2.14 + T2.15 + T2.16 | `AdminService` (gate), Admin UDS listener, middleware, all agent + operator handlers |

### Verification status as of cf65d17

- `cargo test --tests`: **114 / 114 pass** across 19 test binaries
- `cargo clippy --all-targets -- -D warnings`: **clean**
- `cargo fmt --check`: **clean**
- Schema review gate (T2.4): **closed**, self-reviewed against SPEC §4.6.2
- AgentAuthenticator gate (T2.9): **closed**, constant-time + decoy-on-miss verified
- AdminService gate (T2.12): **closed**, cross-transport invariant + cross-namespace rejection verified

---

## 2. What's left for M2

The PRD-stated M2 acceptance contract is *"all UC-1, UC-2, UC-3, UC-4, UC-5, UC-7 flows demonstrable via the `locksmith` CLI against a running daemon."* The integration tests already prove the flows work via the admin router; the CLI + daemon wiring close the contract.

### Immediate next-session work (~3 hours)

#### A. Wire admin UDS into `main.rs` (~30 min)

The daemon currently only binds the agent listener. The admin UDS listener (`src/admin/uds::bind_and_serve`) is fully implemented but unwired.

In `src/main.rs`, the changes are:
1. Read `config.listen.admin_socket.path` (need to add this to `AppConfig`; field doesn't exist yet — currently the SPEC §4.7.7 shows the shape, but the Rust struct hasn't grown it).
2. Open the SQLite pool via `migrations::open_and_migrate`.
3. Construct `AgentRepository`, `BootstrapTokenRepository`, `AuditRepository`.
4. Construct `BearerAuthenticator`, load `OperatorAuthenticator` from `config.operator_credentials_path` (also new config field).
5. Construct `AdminService` and `UdsState`.
6. Spawn `admin::uds::bind_and_serve(&socket_path, state, coordinator.shutdown_signal())` alongside the existing agent-listener spawn.
7. The `ShutdownCoordinator::drain_or_timeout` needs to wait on both server tasks. Use `tokio::join!` or a `JoinSet`.

Test: `cargo run` against a config with `listen.admin_socket.path: "/tmp/locksmith-test.sock"`, then `socat - UNIX-CONNECT:/tmp/locksmith-test.sock` to poke /admin endpoints manually.

#### B. Minimal `locksmith` CLI (~2–3 hours)

Add a second binary entry to `Cargo.toml`:
```toml
[[bin]]
name = "locksmith-cli"
path = "src/cli/main.rs"
```
Or rename the existing `locksmith` to `locksmith-daemon` and make `locksmith` the CLI — operators primarily talk to the CLI. **Recommend: keep `locksmith` as the CLI, rename the daemon to `locksmithd`.** Matches systemd convention (`sshd`, `nginxd`, etc.).

CLI subcommand surface (T2.22–T2.27 from §6.2):

```
locksmith agent list                          # operator
locksmith agent get <id-or-name>              # operator
locksmith agent register --name X --allowlist anthropic,github  # operator
locksmith agent modify <id> --add-allowlist X --remove-denylist Y
locksmith agent revoke <id> --reason "..."

locksmith bootstrap mint --allowlist X,Y --single-use --expires-in 1h
locksmith bootstrap list
locksmith bootstrap revoke <id>

locksmith status                              # agent self-service (uses LOCKSMITH_AGENT_TOKEN)
locksmith rotate                              # agent self-service

locksmith tool list                           # operator
```

Implementation pattern:
- `src/cli/main.rs`: clap subcommand parsing; dispatch to `src/cli/commands/*.rs`.
- HTTP-over-UDS client using `hyper-util::client::legacy::Client` with a `UnixConnector`. The reqwest crate doesn't natively support UDS; use hyper directly. There are crates like `hyperlocal` that simplify this.
- Token sourcing:
  - Operator commands: `LOCKSMITH_OP_TOKEN` env var (or `--token-env <VAR>`).
  - Agent self-service: `LOCKSMITH_AGENT_TOKEN` env var.
- Output formats: `--format table|json|yaml`. Default table; spec UX is in SPEC §4.7.4 (sample invocations) and §4.7.7.
- Exit codes: 0 success / 1 generic / 2 usage / 3 auth / 4 not-found / 5 conflict (per §4.7.2).

Test pattern: spawn the daemon as a child process with a temp socket path and a temp database, then drive each CLI subcommand against it. The integration tests in `tests/admin_uds_test.rs` already demonstrate the full flow at the router level — the CLI tests just verify the wire format is correct.

### Deferred to M2.x (do not block M2 merge on these)

| Task | Issue | Reason for deferral |
|------|-------|---------------------|
| T2.11 RateLimiter | #24 | Defensive; not blocking UC demonstrability. Operators can front Locksmith with nginx/Caddy for rate limiting in the meantime. |
| T2.17 typed `SecretRef` | (not yet filed) | Schema evolution for credential refs. Field-scoped `${VAR}` already works. |
| T2.18 field-scoped `${VAR}` expansion | (not yet filed) | Already implemented in M1 by accident — the M0 textual expander handles the dominant case. INF-23's deprecation path lands the typed form when needed. |
| T2.19 `SecretBackend` trait + `EnvBackend` | (not yet filed) | Env backend already implicitly works. M5 ships file-sealed; the trait can be retrofitted then. |
| T2.20 Hot reload + listener-shape carve-out | (not yet filed) | M0's ArcSwap primitive is in place; full reload logic is M2.x. |
| T2.21 Startup-check sequencing (INF-2) | (not yet filed) | Daemon is currently fail-fast on the path that matters (DB unreachable). Comprehensive INF-2 is M2.x. |
| T2.28–T2.29 `bench` subcommands | (not yet filed) | A-1 assumption verification; useful but not blocking. |

### Open follow-ups discovered during M2

| Finding | Where | Status |
|---------|-------|--------|
| INF-13 audit-on-failure not yet wired | `auth_v2::BearerAuthenticator`, `AdminService` | Authenticator/service surface typed errors; AuditRepository.record will be called on the error path in M3 (T3.1, T3.2). |
| `last_used_at` touch is best-effort | `auth_v2::agent.rs::resolve` | Acceptable per SPEC §4.2.10; document in operator runbook. |
| Operator scope reserved but not enforced | All operator handlers in `admin::service` | D-6 reserved field. v1 operator credentials are all-or-nothing. |

---

## 3. Conventions and gotchas (discovered during M1 + M2)

### Token wire format

- **Agent**: `lk_<22-char-base64-id>.<43-char-base64-secret>`
- **Operator**: `lkop_<id>.<secret>`
- **Bootstrap**: `lkbt_<id>.<secret>`

**Single-underscore separator only.** The original SPEC implied `lk_op_…` but that breaks the `split_once('_')` parser. We use `lkop`/`lkbt` (no embedded underscore) for operator and bootstrap namespaces. SPEC §4.2.8 reflects this.

### Deprecation registry (INF-24)

`src/deprecation.rs` is the single mechanism for renamed/removed fields. Currently registered:

- `tools[].cloud` → renamed to `tools[].egress` (M1)
- `telemetry` → removed (M1; was M0 dead code)
- `tools[].timeout_seconds` → renamed to `tools[].timeouts.request_seconds` (M1)

Add new entries here when removing/renaming any config field. The mechanism guarantees one-shot warnings per process.

### YAML config parsing pipeline

`config::parse_config_str` is the canonical entry. The pipeline:
1. `expand_env_vars` (textual `${VAR}` → env value)
2. Untyped `serde_yaml::Value` parse
3. `apply_deprecations` (in-place tree edits per registry)
4. Typed `serde_yaml::from_value::<AppConfig>` with `deny_unknown_fields`

**Tests must use `parse_config_str`, not `serde_yaml::from_str` directly.** The latter bypasses the deprecation translation and `deny_unknown_fields` will reject any legacy YAML.

### SQLite migrations

- Migration files cannot contain `PRAGMA synchronous` or `PRAGMA journal_mode` — sqlx wraps each migration in a transaction, and SQLite forbids those PRAGMAs in transactions. They're applied at connection-open via `SqliteConnectOptions` + `after_connect` hook.
- WAL is on; `wal_autocheckpoint = 1000` is in the after-connect hook.
- Forward-only per INF-11. Rollback = backup + restore.

### Token namespace mapping

When adding a new `TokenNamespace` variant, update both `prefix()` and `from_prefix()` in `src/token.rs`. Cross-namespace rejection is verified by integration tests; don't break those.

### argon2 parameters

`m=4096 KiB (4 MiB), t=3, p=1` (Q-13). ~5ms verify on commodity hardware. Configurable via `argon2_helper::argon2()` if the assumption A-1 misses.

### Decoy-on-miss in authenticators

Both `BearerAuthenticator` and `OperatorAuthenticator` precompute a stored decoy hash at construction. On any "this credential isn't valid" path (public_id miss, malformed token, wrong namespace), they still run an argon2 verify against the decoy so the timing channel is closed. **Don't optimize this away; it's a security property the gate review verified.**

### Test infrastructure

- **`wiremock` (already a dev-dep)** for fixture upstreams in proxy tests.
- **`tempfile`** for ephemeral SQLite files in repository tests.
- **`axum_test::TestServer`** — note the v19 API: `TestServer::new(router)` (no `.unwrap()`).
- **No mocks for repos** — repository tests run against real (in-memory or temp-file) SQLite via `migrations::open_and_migrate`. London-style integration testing per the kickoff TDD mandate.

### Cloud provider tests

`tests/inference_matrix_cloud_test.rs` is local-only per Q-2. CI never runs it; engineers run pre-PR with `ANTHROPIC_API_KEY` and `OPENAI_API_KEY` set.

### CI mismatch with local toolchain

Local Rust 1.88+ has stricter `clippy` defaults than the CI's `dtolnay/rust-toolchain@stable`. Watch for `uninlined_format_args` and `redundant_closure` lints fired locally that don't fire in CI. Always run `cargo clippy --all-targets -- -D warnings` locally before commit.

---

## 4. Where to look

| Need | Read |
|------|------|
| Why we're building this | `docs/v2/PRD.md` — vision, customers, use cases, requirements, milestones, decisions |
| How we're building it | `docs/v2/SPEC.md` — full design produced from the PRD via the SoftwareDesign skill |
| What the schema looks like and why | SPEC §4.6.2 (DDL) and §4.2.10/§4.2.11/§4.2.12 (repositories) |
| What the admin endpoints are | SPEC §5 Q2 (consolidated table) |
| Operator-facing UX | SPEC §4.7 — sample CLI invocations, YAML configs, HTTP error envelopes |
| Implementation plan | SPEC §6.2 — the canonical task list |
| Verification policy | SPEC §6.4.1 — which tasks are gates, why, and the procedure |
| What was decided and why | SPEC §15 — preserved D-1..D-18 from PRD, plus 28 resolved questions in §2 |
| The 26 inferred design requirements | SPEC Appendix B.4 — INF-1..INF-26 |
| Deployment-time assumptions to validate | SPEC §2.1 — A-1..A-4 |
| M1 acceptance procedure | `docs/v2/runbooks/m1-inference-hardening.md` |

---

## 5. Resuming

```bash
# Get the branch and the latest test state.
git fetch
git checkout m2/implementation
git pull

# Sanity check.
cargo test --tests
cargo clippy --all-targets -- -D warnings
cargo fmt --check

# Read this file (you're doing it).
# Read SPEC.md §6.2 T2.22..T2.29 for CLI scope.
# Read SPEC.md §4.7 for the CLI UX surface.

# Then:
# 1. Branch from m2/implementation for the daemon wiring + CLI work, OR
#    just continue on m2/implementation if you're confident.
# 2. Wire admin/uds::bind_and_serve into main.rs first (~30 min).
# 3. Build the CLI subcommand by subcommand, following the §4.7 UX surface.
# 4. End-to-end test: spawn daemon, run CLI commands, verify the UC flows.
```

When M2 is acceptance-ready:

```bash
# Return to develop and merge.
git checkout develop
git merge --no-ff m2/implementation -m "Merge m2/implementation: M2 (agent identity + admin substrate) complete"
git push

# Close any remaining M2 issues with the merge SHA.
# Bump version: 0.3.0 per SPEC §6.4 release-versioning map.
# Tag the release: git tag v0.3.0 && git push origin v0.3.0
```

---

## 6. Workflow policies (don't drift from these)

These came from the PRD §kickoff and SPEC §6.4. They've held all the way through M1 and M2 and should keep holding.

- **TDD per task** (`superpowers:test-driven-development`). Failing test first; implement to green. Integration tests for behavior, unit tests for module-internal logic.
- **Verification gates** at T6.2/T6.5 (MtlsValidator + MtlsAuthenticator), T6.7 (operator mTLS), and M3 closure (audit retention correctness). Self-review or `devloop:local-review` before merge — not after.
- **Conventional commits** with the milestone in the subject and `Closes #N` in the body. `Closes` only auto-closes on merges to the *default* branch (which is `main`). Since we merge to `develop`, manually `gh issue close` after each merge.
- **Issues created proactively** for upcoming tasks (one issue per §6.2 task). Apply labels: `milestone:M{N}`, `component:*`, `layer:*`, `kind:*`, `risk:*`, plus per-requirement labels (`R-F12`, `UC-6`, `INF-25`).
- **No PRs required** for this project — direct merge to `develop` is the standing instruction.
- **Schema/auth/admin gates require self-review** before merge (per §6.4.2). The session that closed gates T2.4, T2.9, T2.12 documented the review inline in commit messages.

---

## 7. What success looks like for the next session

A single deliverable: **`cargo run` starts the daemon with both listeners bound, and `locksmith agent register --name foo` succeeds against it.** That demonstrates UC-1 end-to-end via the CLI — the M2 acceptance contract.

After that, the path to v1.0.0 (M7 closure) is the ordered milestone walk in SPEC §6.2.

---

*End of handoff. Push back on anything in this document that turns out wrong; update it as you go so the next handoff is accurate.*
