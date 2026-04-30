# Handoff — Agent Locksmith v2 Implementation

**Last updated:** 2026-04-29
**Default working branch:** `develop` (M3 merged via `m3/audit-pipeline`)

This document is the cold-start context for the next session. Read top to bottom before touching code.

---

## 1. Where we are

| Branch | State | What's there |
|--------|-------|--------------|
| `main` | Stable | M0 implementation. CI passes. |
| `develop` | M3 closure | M0 + M1 + M2 + M3. The audit pipeline is complete: writes from proxy + admin paths, JSONL mirror, retention sweep, operator query CLI, audit-on-failure, agent export. **Default working branch.** |
| `m3/audit-pipeline` | Merged | Kept for archaeology. |

### What's merged into `develop`

- v2 PRD + design (SoftwareDesign workflow, all 7 phases).
- **M1** (T1.1–T1.13): inference-ready hardening.
- **M2** (T2.1–T2.10, T2.12–T2.16, T2.22–T2.27): agent identity + admin substrate + locksmith CLI.
- **M3 acceptance contract** met (see §2).

### Test + lint state at M3 closure

- `cargo test --tests`: **160 / 160 pass** across 27 test binaries.
- `cargo clippy --all-targets -- -D warnings`: clean.
- `cargo fmt --check`: clean.

### M3 task progress (per SPEC §6.2)

| Task | Status | Notes |
|------|--------|-------|
| T3.1 — proxy hot-path audit | ✅ | One row per request; tool/method/path/status/latency/decision; agent_public_id None pending per-agent proxy auth (M3.x). |
| T3.2 — admin path audit | ✅ | One row per state-mutating call; success + failure paths covered. |
| T3.3 — retention worker | ✅ | 90-day default; hourly cadence; verification gate closed. |
| T3.4 — JSONL sink | ✅ | Daily + cap rotation; 100 MiB default; `keep_files=14`. |
| T3.5 — JSONL fan-out wired into AuditRepository | ✅ | After SQL commit; best-effort on JSONL failure. |
| T3.6 — `locksmith audit query` | ✅ | Filters by agent/tool/event_class/decision/since/until. |
| T3.7 — `locksmith audit tail` | ⏳ Deferred | Streaming follow endpoint; needs SSE or websocket. M3.x. |
| T3.8 — `locksmith export agents` | ✅ | UC-10. Excludes token material per R-F14. |
| T3.9 — bench task | ⏳ Deferred | A-2 / INF-26 verification. M3.x. |
| T3.10 — conditional async-batched | ⏳ Deferred | Only triggered by T3.9. M3.x. |
| T3.11 — audit-class review | ✅ | Revocation events moved to Security class. |

### Verification gates closed

| Task | Status |
|------|--------|
| T2.4 schema | Closed in M2 |
| T2.9 AgentAuthenticator | Closed in M2 |
| T2.12 AdminService | Closed in M2 |
| T3.3 retention worker | Closed in M3 (this session) |

---

## 2. M3 acceptance demo

The M3 contract — *"queryable by operator + retention sweeper observable"* — is met:

```bash
# (1) Run the daemon (M2 wiring still applies; just add an audit block).
cat > /etc/locksmith/config.yaml <<EOF
listen:
  host: "127.0.0.1"
  port: 9200
  admin_socket:
    path: "/var/run/locksmith/admin.sock"
operator_credentials_path: "/etc/locksmith/operators.yaml"
database:
  path: "/var/lib/locksmith/locksmith.db"
audit:
  retention_days: 90
  sweep_interval_seconds: 3600
  jsonl_path: "/var/log/locksmith/audit.jsonl"
tools: []
EOF
locksmithd --config /etc/locksmith/config.yaml &

# (2) Operator generates events.
export LOCKSMITH_OP_TOKEN=lkop_...
locksmith agent register --name agent-alpha
locksmith bootstrap mint --reusable

# (3) Operator queries audit.
locksmith audit query --event-class operator
locksmith audit query --decision denied --limit 10

# (4) JSONL mirror is tail-able.
tail -f /var/log/locksmith/audit.jsonl.$(date -u +%F)

# (5) UC-10 export.
locksmith export agents --format yaml > agents.yaml
```

---

## 3. What's left for M3.x and M4

### M3.x carry-overs

| Task | Why deferred |
|------|--------------|
| T3.7 audit tail | Streaming follow needs SSE wiring. Not blocking M4. |
| T3.9 bench | A-2 / INF-26 verification; can land any time pre-v1.0. |
| T3.10 conditional async fallback | Only if T3.9 trips. |

### M4 — Admin HTTPS surface

SPEC §6.2 T4.*. Same admin operations available over TLS for remote management. Adds `listen.admin_https` block and a separate Tower service that reuses AdminService.

Dependencies: M3. Audit is the discoverable surface that makes a remotely-managed daemon valuable.

---

## 4. Conventions and gotchas

### Audit data model

- `audit` table: 15 columns. Two CHECK-constrained enums (event_class, decision). See `migrations/0001_init.sql`.
- `EventClass::Operator` for state-mutating non-revocation admin actions.
- `EventClass::Security` for: auth_failure, operator_auth_failure, bootstrap_reuse_attempt, agent_revoke, agent_deregister, bootstrap_revoke. Revocation is security because it changes trust posture (T3.11 review).
- `EventClass::Proxy` for proxy hot-path events.
- `Decision::Allowed` / `Denied` / `Error`. Allowed = success. Denied = policy/auth refused. Error = upstream/system fault.

### Audit invariants (do not break)

- **Audit must never block proxy traffic** (INF-26). All audit calls in `record()`, `JsonlSink::append`, and `audit_*_failure` helpers swallow errors via `tracing::warn!`.
- **JSONL fan-out happens AFTER SQL commit**, so SQL is canonical and JSONL mirrors. If JSONL fails, SQL still has the row.
- **Retention sweep is bounded to the audit table**; the `sweep_does_not_touch_other_tables` test pins this.

### Token wire format

- Agent: `lk_<id>.<secret>`
- Operator: `lkop_<id>.<secret>`
- Bootstrap: `lkbt_<id>.<secret>`

### Two binaries

- `locksmithd` — daemon (`src/main.rs`)
- `locksmith` — CLI (`src/cli/main.rs`)

CLI subcommands: `agent`, `bootstrap`, `tool`, `audit`, `export`, `status`, `rotate`.

### Daemon runtime

`src/daemon.rs::run` is the canonical entry. It validates the admin substrate triple (`listen.admin_socket` + `database.path` + `operator_credentials_path`), opens SQLite, builds the JSONL sink (if configured), constructs repos/auth/AdminService, spawns the agent listener + admin UDS + retention sweeper against a shared `ShutdownCoordinator`. The drain window awaits all three.

`AppState.config` is `Arc<ArcSwap<AppConfig>>`. The agent listener and AdminService share this snapshot.

### UDS HTTP client

`src/admin/uds_client.rs`: minimal hyper 1.x http1 over `tokio::net::UnixStream`. No hyperlocal dep, no pool. Each CLI call is a fresh connection.

### CLI exit codes (§4.7.2)

`0` ok | `1` generic | `2` usage | `3` auth | `4` not-found | `5` conflict.

### Config blocks (M3 additions)

```yaml
audit:
  retention_days: 90              # default
  sweep_interval_seconds: 3600    # default (hourly)
  jsonl_path: "/var/log/..."      # optional; absent = SQL only
  jsonl_max_bytes: 104857600      # default 100 MiB
  jsonl_keep_files: 14            # default
```

### YAML config parsing pipeline

`config::parse_config_str` is the canonical entry. Pipeline: env-var expansion → untyped YAML → deprecation registry → typed deserialize with `deny_unknown_fields`. Tests must use this entry; `serde_yaml::from_str` directly skips the deprecation translations.

### SQLite migrations

- Forward-only. Rollback = backup + restore.
- PRAGMAs that can't live in a transaction (synchronous, journal_mode) are applied at connection-open via `SqliteConnectOptions` + the `after_connect` hook.

### argon2 parameters

`m=4096 KiB, t=3, p=1` (Q-13). ~5ms verify on commodity hardware.

### Decoy-on-miss in authenticators

Both `BearerAuthenticator` and `OperatorAuthenticator` precompute a stored decoy hash. On invalid-credential paths they still run an argon2 verify against the decoy. Don't optimize this away — it's a security property that gate review verified.

### CI mismatch with local toolchain

Rust 1.88+ has stricter clippy defaults than CI. Always `cargo clippy --all-targets -- -D warnings` locally before commit.

### `gh` keyring quirk

Stale `GITHUB_TOKEN` env overrides keyring auth. Always invoke as `env -u GITHUB_TOKEN gh ...`.

---

## 5. Where to look

| Need | Read |
|------|------|
| Why we're building this | `docs/v2/PRD.md` |
| How we're building it | `docs/v2/SPEC.md` |
| Schema | SPEC §4.6.2 + `migrations/0001_init.sql` |
| Admin endpoints | SPEC §5 Q2 + `src/admin/uds.rs` |
| Operator-facing UX | SPEC §4.7 |
| Implementation plan | SPEC §6.2 (canonical task list) |
| Verification policy | SPEC §6.4.1 |
| Decisions | SPEC §15 (D-1..D-18) + §2 (28 resolved questions) |
| Inferred design requirements | SPEC Appendix B.4 (INF-1..INF-26) |
| Deployment-time assumptions | SPEC §2.1 (A-1..A-4) |
| M1 acceptance | `docs/v2/runbooks/m1-inference-hardening.md` |

---

## 6. Resuming for M3.x or M4

```bash
git fetch
git checkout develop
git pull

cargo test --tests
cargo clippy --all-targets -- -D warnings
cargo fmt --check

# Branch off develop for M4.
git checkout -b m4/admin-https
```

Workflow that has held through M1 + M2 + M3:

- TDD per task (`superpowers:test-driven-development`): failing test first.
- Verification gates with self-review before merge: closed T2.4, T2.9, T2.12, T3.3.
- Conventional commits with milestone in subject and `Closes #N` in body.
- Issues filed proactively (one per §6.2 task) with milestone/component/layer/kind/risk + per-requirement labels.
- No PRs required — direct merge to `develop`. `gh issue close` manually since auto-close only fires on merges to default branch.

---

## 7. What success looks like for the next session

If continuing M3.x: T3.7 audit tail (streaming follow) + T3.9 bench. Both small, both round out M3 before M4.

If jumping to M4 (admin HTTPS):
1. Add `listen.admin_https` config block (host, port, cert_path, key_path).
2. Reuse the existing `admin/uds.rs::build_router` with TLS termination.
3. Cross-transport invariant: HTTPS surface and UDS surface return identical responses for identical requests.
4. M4 acceptance contract: `locksmith --remote https://...` works (CLI gains a `--remote` flag for the HTTPS path).

---

*End of handoff. Push back on anything that turns out wrong; update as you go.*
