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

## 3. What's left to ship v1.0.0

Roughly half of v2 by task count remains. Four milestones (M4..M7), plus M2.x / M3.x carry-overs that can land any time.

### Milestone walk to v1.0.0

| Milestone | Version | Tasks | Goal | Verification gates |
|-----------|---------|-------|------|--------------------|
| **M4** | v0.5.0 | T4.1–T4.6 (~6) | Admin HTTPS for remote management. Reuses AdminService; same handlers as UDS. | — (low risk) |
| **M5** | v0.6.0 | T5.1–T5.5 (~5) | Keys-at-rest hardening: file-sealed `SecretBackend`, systemd hardening directives, threat-model doc. Vault + AWS land as trait stubs only. | — |
| **M6** | v0.7.0 | T6.1–T6.11 (~11; biggest) | mTLS for agents + operators. CRL fetcher, local emergency blocklist, bootstrap-only listener (C-4), `auth_mode: bearer | mtls | both`. | **T6.2 + T6.5** (MtlsValidator + MtlsAuthenticator), **T6.7** (operator mTLS) |
| **M7** | v1.0.0 | T7.1–T7.4 (~4) | Per-tool response controls: max_size_bytes, content_type_allowlist, regex redaction. Streaming preserved (only total-size cap applies). | — |

### M4 — Admin HTTPS (next session)

**Goal:** Operators run all CLI operations remotely via `--admin-url https://locksmith.example.com:9201`. Same handlers as the UDS, bindable to a separate listener, off-by-default.

| Task | Summary |
|------|---------|
| T4.1 | Server-side rustls deps (`rustls-pemfile`, `tokio-rustls` or `axum-server`'s rustls feature) |
| T4.2 | Cert/key loading + fail-fast on missing/bad PEM |
| T4.3 | Admin HTTPS listener; reuse C-12 AdminService and the C-2 handler functions |
| T4.4 | CLI auto-detect: `LOCKSMITH_ADMIN_URL` env or `--admin-url` flag; fall back to UDS |
| T4.5 | Bootstrap-token register works over HTTPS regardless of `auth_mode` (D-10) |
| T4.6 | Cert-rotation listener-shape carve-out (cert/key paths require restart) |

**Acceptance:** Identical results between UDS and HTTPS for every admin operation.

**Config additions to anticipate:**
```yaml
listen:
  admin_https:
    enabled: false          # off by default
    host: "127.0.0.1"
    port: 9201
    cert_path: "/etc/locksmith/tls/server.crt"
    key_path: "/etc/locksmith/tls/server.key"
```

### M5 — Keys-at-rest

**Goal:** No upstream credentials in env or operator-readable config. systemd unit ships hardened.

| Task | Summary |
|------|---------|
| T5.1 | `FileSealedBackend`: read sealed file, decrypt via systemd-creds (or configured key), zeroize on drop |
| T5.2 | `dist/systemd/locksmith.service.template` with `NoNewPrivileges`, `ProtectSystem=strict`, `PrivateTmp`, dedicated `locksmith` user |
| T5.3 | `VaultBackend` + `AwsSecretsManagerBackend` *trait stubs* only (signatures + rustdoc; not registered in dispatch) |
| T5.4 | `docs/v2/threat-model.md`: what at-rest hardening protects against; what it doesn't (process memory, kernel exploits, root) |
| T5.5 | Worked openclaw-hardened example at `dist/examples/sealed-secrets/` |

### M6 — mTLS (likely 2 sessions)

**Goal:** Cryptographic identity for agents AND operators. Two-session split recommended:

**Session A — Agent-side mTLS (T6.1–T6.5 + gate):**
- T6.1 deps (`x509-parser`; `rcgen` dev-dep for test cert minting)
- T6.2 **MtlsValidator gate** — chain validation against CA bundle, expiration, identity extraction (CN / SAN_DNS / SAN_URI)
- T6.3 CRL fetcher (periodic background task; metrics: `mtls_crl_refresh_failures_total`, `mtls_crl_age_seconds`)
- T6.4 Local emergency blocklist with hot reload
- T6.5 **MtlsAuthenticator gate** — implements `AgentAuthenticator`; maps cert identity to agent via `AgentRepository.get_by_cert_identity`

**Session B — auth_mode + operator mTLS + tooling (T6.6–T6.11 + gate):**
- T6.6 `auth_mode: bearer | mtls | both`; `both` tries mTLS first, falls back to bearer
- T6.7 **Operator mTLS gate** — admin HTTPS accepts operator client certs; operators.yaml gains optional `cert_identity` field (D-9)
- T6.8 Bootstrap-only listener (C-4): single endpoint `POST /admin/agent/register`
- T6.9 `locksmith mtls revoke <serial>`, `locksmith mtls list-blocklist`, `locksmith mtls crl-status`
- T6.10 Audit `auth_method` field on every authenticated request (`bearer` / `mtls` / `bootstrap` / `operator`)
- T6.11 Worked smallstep + step-ca example at `dist/examples/smallstep/`

### M7 — Response controls (final milestone)

**Goal:** Per-tool max_size_bytes, content_type_allowlist, regex redaction. Streaming first-byte latency must stay ≤100ms (R-N6).

| Task | Summary |
|------|---------|
| T7.1 | `tools[].response: { max_size_bytes, content_type_allowlist, redaction_patterns }` |
| T7.2 | `ResponseControls.apply` for non-streaming (read body, check content-type, apply redaction) |
| T7.3 | Streaming wrapper: byte-counter `Stream` adapter that emits truncation marker on cap-exceeded |
| T7.4 | Audit events: `response_redaction` (with hash of match, NOT cleartext) and `response_size_exceeded` |

**Regression check:** rerun M1 streaming tests with response controls enabled.

### Carry-overs (deferred; can land any time)

**M2.x:**
| Task | Notes |
|------|-------|
| T2.11 RateLimiter | Issue #24. Defensive; nginx/Caddy in front works as a stopgap. |
| T2.17 typed `SecretRef` | Schema evolution. Field-scoped `${VAR}` works today. |
| T2.18 field-scoped `${VAR}` | M0 textual expander handles dominant case. |
| T2.19 `SecretBackend` trait + `EnvBackend` | Env backend works implicitly; trait formalization is M5 territory. |
| T2.20 hot reload + listener-shape carve-out | M0 ArcSwap is in place; full reload logic is here. |
| T2.21 startup-check sequencing (INF-2) | Daemon already fail-fast on the path that matters. |
| T2.27 `locksmith config reload/show` | Useful but not critical for M4. |
| T2.28/T2.29 bench subcommands | A-1 verification; useful, not blocking. |

**M3.x:**
| Task | Notes |
|------|-------|
| T3.7 `locksmith audit tail` | Streaming follow; needs SSE endpoint. |
| T3.9 audit-write bench | A-2 / INF-26 validation; **must run before v1.0.0 cut**. |
| T3.10 conditional async-batched | Only if T3.9 trips the >5ms p95 trigger. |

### Pre-v1.0.0 closure checklist

- [ ] All four remaining milestones merged.
- [ ] M3 audit-write bench (T3.9) executed; report attached to closure issue.
- [ ] If trigger tripped, T3.10 async-batched landed.
- [ ] All verification gates closed with self-review (T6.2, T6.5, T6.7).
- [ ] Threat model (`docs/v2/threat-model.md`) reviewed and merged.
- [ ] Per-milestone runbooks (m4-remote-management, m5-sealed-secrets, m6-mtls-{onboarding,migration,revocation}, m7-response-controls) shipped.
- [ ] §7 changelog v1.0.0 entry written.

**Rough estimate: 5–7 working sessions of similar density to land v1.0.0.**

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

## 6. Resuming the next session

```bash
git fetch
git checkout develop
git pull

# Sanity check current state (160/160, clean lint).
cargo test --tests
cargo clippy --all-targets -- -D warnings
cargo fmt --check

# Branch off develop for M4 (recommended next).
git checkout -b m4/admin-https
```

Workflow that has held through M1 + M2 + M3 (and should keep holding):

- **TDD per task** (`superpowers:test-driven-development`): failing test first; do not write production code without a failing test that justifies it.
- **Verification gates self-reviewed before merge**: closed so far T2.4 (schema), T2.9 (AgentAuthenticator), T2.12 (AdminService), T3.3 (retention). Coming: T6.2 + T6.5 (mTLS validator + authenticator), T6.7 (operator mTLS).
- **Conventional commits** with the milestone in the subject and `Closes #N` in the body. `Closes` only auto-closes on merges to default branch (which is `main`); since we merge to `develop`, manually `gh issue close` after each merge.
- **Issues filed proactively** (one per §6.2 task) with labels: `milestone:M{N}`, `component:*`, `layer:*`, `kind:*`, `risk:*`, plus per-requirement labels (`R-F12`, `UC-6`, `INF-25`).
- **No PRs required** for this project — direct merge to `develop` is the standing instruction.
- **Per-milestone close-out:** branch → tasks → tests/lint → commit/push → close issues → merge `--no-ff` to `develop` → bump version → tag `v0.{milestone+1}.0` → refresh this handoff. M2 and M3 closure followed this exactly.

---

## 7. What success looks like for the next session

**Recommended target: M4 (admin HTTPS).** Six tasks, no verification gate, ~1 session. Closes the remote-management hole so that operators of openclaw-hardened deployments stop needing host-shell access.

Concrete acceptance for the next session:
1. `listen.admin_https` config block parses (host, port, cert_path, key_path, `enabled: false` default).
2. `locksmithd` binds the HTTPS listener when enabled and rejects unknown TLS PEM at startup (fail-fast).
3. `locksmith --admin-url https://...` reaches the same handlers as the UDS path — assertion: identical JSON responses for `agent list`, `agent register`, `audit query`, `bootstrap mint`.
4. Bootstrap-token register works over HTTPS regardless of `auth_mode` (D-10 invariant).
5. Cert/key paths require restart (listener-shape carve-out, T4.6).
6. `tests/admin_https_test.rs` + `tests/admin_https_off_by_default_test.rs` both pass.
7. End of session: merge → `v0.5.0` → tag.

If you go for M4 + an M3.x carry-over, **T3.9 (audit-write bench)** is the highest-value follow-up — it formally validates A-2 / INF-26 and is a pre-v1.0.0 closure-checklist item.

After M4: M5 keys-at-rest, then M6 mTLS (the biggest milestone — likely two sessions split at the T6.5 / T6.7 gate boundary), then M7 response controls = v1.0.0.

The path to v1.0.0 from here is concrete and fits in 5–7 sessions of similar density to the M2 + M3 sessions.

---

*End of handoff. Push back on anything that turns out wrong; update as you go.*
