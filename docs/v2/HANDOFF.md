# Handoff — Agent Locksmith v2 Implementation

**Last updated:** 2026-04-29
**Default working branch:** `develop` (M4 merged via `m4/admin-https`)

This document is the cold-start context for the next session. Read top to bottom before touching code.

---

## 1. Where we are

| Branch | State | What's there |
|--------|-------|--------------|
| `main` | Stable | M0 implementation. CI passes. |
| `develop` | M4 closure | M0 + M1 + M2 + M3 + M4. Admin HTTPS listener available alongside UDS; CLI auto-detects `--admin-url` / `LOCKSMITH_ADMIN_URL`. **Default working branch.** Tagged **v0.5.0**. |
| `m3/audit-pipeline` | Merged | Kept for archaeology. |
| `m4/admin-https` | Merged | Kept for archaeology. |

### What's merged into `develop`

- v2 PRD + design (SoftwareDesign workflow, all 7 phases).
- **M1** (T1.1–T1.13): inference-ready hardening.
- **M2** (T2.1–T2.10, T2.12–T2.16, T2.22–T2.27): agent identity + admin substrate + locksmith CLI.
- **M3** (T3.1–T3.6, T3.8, T3.11): governance audit log.
- **M4** (T4.1–T4.6): admin HTTPS listener for remote management.

### Test + lint state at M4 closure

- `cargo test --tests`: **170 / 170 pass** across 31 test binaries.
- `cargo clippy --all-targets -- -D warnings`: clean.
- `cargo fmt --check`: clean.

### M4 task progress (per SPEC §6.2)

| Task | Status | Notes |
|------|--------|-------|
| T4.1 — server-side rustls deps | ✅ | `axum-server` 0.7 + `rustls` 0.23 (aws-lc-rs explicit) + `rcgen` 0.13 dev-dep. |
| T4.2 — TLS cert/key load + fail-fast | ✅ | `admin::https::load_tls_config`; 4 unit tests for missing cert / missing key / malformed PEM / valid. |
| T4.3 — admin HTTPS listener | ✅ | `src/admin/https.rs` reuses `uds::build_router` exactly; off-by-default. 2 round-trip tests + 2 off-by-default tests. |
| T4.4 — CLI auto-detect | ✅ | `--admin-url` / `LOCKSMITH_ADMIN_URL` and `--ca-bundle` / `LOCKSMITH_CA_BUNDLE`; CliClient is a Transport enum (Uds / Https). |
| T4.5 — bootstrap register over HTTPS | ✅ | D-10 invariant preserved automatically (same router). |
| T4.6 — listener-shape carve-out + runbook | ✅ | `docs/v2/runbooks/m4-remote-management.md` shipped. Cert/key paths documented as restart-only. |

### Verification gates closed

| Task | Status |
|------|--------|
| T2.4 schema | Closed in M2 |
| T2.9 AgentAuthenticator | Closed in M2 |
| T2.12 AdminService | Closed in M2 |
| T3.3 retention worker | Closed in M3 |

M4 had no verification gate (low-risk per SPEC §6.2). Coming gates: **T6.2** + **T6.5** (mTLS validator + authenticator), **T6.7** (operator mTLS).

---

## 2. M4 acceptance demo

The M4 contract — *"identical results between CLI-via-UDS and CLI-via-HTTPS for every admin operation"* — is met. The full verification matrix is in `docs/v2/runbooks/m4-remote-management.md` §1.

```bash
# (1) Generate cert + key (smallstep / step-ca for prod; openssl for dev).
openssl req -x509 -newkey rsa:4096 -nodes -days 365 \
    -keyout /etc/locksmith/tls/server.key \
    -out /etc/locksmith/tls/server.crt \
    -subj "/CN=locksmith.local" \
    -addext "subjectAltName=DNS:locksmith.local,IP:127.0.0.1"

# (2) Add admin_https block to the daemon config.
cat >> /etc/locksmith/config.yaml <<EOF
listen:
  admin_https:
    enabled: true
    host: "0.0.0.0"
    port: 9201
    cert_path: "/etc/locksmith/tls/server.crt"
    key_path: "/etc/locksmith/tls/server.key"
EOF
locksmithd --config /etc/locksmith/config.yaml &

# (3) Operator runs CLI remotely. UDS path no longer required.
export LOCKSMITH_ADMIN_URL="https://locksmith.example.com:9201"
export LOCKSMITH_CA_BUNDLE="/etc/ssl/certs/locksmith-ca.crt"   # private CA
export LOCKSMITH_OP_TOKEN="lkop_..."

locksmith agent list
locksmith agent register --name agent-frontend
locksmith audit query --event-class operator --limit 50

# (4) Bootstrap-token register works over HTTPS WITHOUT the operator
#     bearer (D-10): the agent host gets the bootstrap token and that's
#     the only credential it needs.
curl -X POST https://locksmith.example.com:9201/admin/agent/register \
    --cacert /etc/ssl/certs/locksmith-ca.crt \
    -H 'content-type: application/json' \
    -d '{"bootstrap_token":"lkbt_...","name":"agent-X"}'

# (5) UDS path still works. Identical JSON output for the same op.
locksmith --socket /var/run/locksmith/admin.sock agent list
```

---

## 3. What's left to ship v1.0.0

Three milestones remain (M5..M7), plus M2.x / M3.x carry-overs that can land any time.

### Milestone walk to v1.0.0

| Milestone | Version | Tasks | Goal | Verification gates |
|-----------|---------|-------|------|--------------------|
| ~~M4~~ | ~~v0.5.0~~ | ~~T4.1–T4.6~~ | ~~Admin HTTPS for remote management.~~ | ~~—~~ ✅ Closed |
| **M5** | v0.6.0 | T5.1–T5.5 (~5; bundles T2.17 + T2.19) | Keys-at-rest hardening: file-sealed `SecretBackend`, systemd hardening directives, threat-model doc. Vault + AWS land as trait stubs only. | — |
| **M6** | v0.7.0 | T6.1–T6.11 (~11; biggest) | mTLS for agents + operators. CRL fetcher, local emergency blocklist, bootstrap-only listener (C-4), `auth_mode: bearer | mtls | both`. | **T6.2 + T6.5** (MtlsValidator + MtlsAuthenticator), **T6.7** (operator mTLS) |
| **M7** | v1.0.0 | T7.1–T7.4 (~4) | Per-tool response controls: max_size_bytes, content_type_allowlist, regex redaction. Streaming preserved (only total-size cap applies). | — |

### M5 — Keys-at-rest (next session)

**Goal:** No upstream credentials in env or operator-readable config. systemd unit ships hardened.

**Coupling note (read first):** SPEC T5.1 says *"read sealed-secret file path from `SecretRef::FromFileSealed`"* — so M5 effectively bundles two M2.x carry-overs that until now had no consumer:

- **T2.17** (typed `SecretRef`): `tools[].auth.value` becomes an enum `{ Inline | FromEnv | FromFileSealed }` instead of a raw `SecretString`.
- **T2.19** (`SecretBackend` trait + `EnvBackend`): the dispatch surface that `FileSealedBackend` plugs into.

These are the right tasks to land first — start with T2.17 + T2.19, then T5.1 has a place to plug in. T2.18 (field-scoped `${VAR}`) can stay deferred; the M0 textual expander still covers the dominant case.

| Task | Summary |
|------|---------|
| T2.17 (carry-over) | Typed `SecretRef` enum replacing `auth.value: SecretString`; backward-compat shim accepts plain string as `Inline` per INF-24 |
| T2.19 (carry-over) | `SecretBackend` trait + `EnvBackend` impl (already implicit; formalize the trait) |
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
| T2.17 typed `SecretRef` | **Lands in M5** as a prereq for T5.1 (FileSealedBackend). |
| T2.18 field-scoped `${VAR}` | M0 textual expander handles dominant case. |
| T2.19 `SecretBackend` trait + `EnvBackend` | **Lands in M5** as the dispatch surface for T5.1. |
| T2.20 hot reload + listener-shape carve-out | M0 ArcSwap is in place; full reload logic is here. The M4 listener-shape fields (`admin_https.{cert_path,key_path,host,port,enabled}`) feed in here when reload lands. |
| T2.21 startup-check sequencing (INF-2) | Daemon already fail-fast on the path that matters. |
| T2.27 `locksmith config reload/show` | Useful but not critical for M5. |
| T2.28/T2.29 bench subcommands | A-1 verification; useful, not blocking. |

**M3.x:**
| Task | Notes |
|------|-------|
| T3.7 `locksmith audit tail` | Streaming follow; needs SSE endpoint. |
| T3.9 audit-write bench | A-2 / INF-26 validation; **must run before v1.0.0 cut**. |
| T3.10 conditional async-batched | Only if T3.9 trips the >5ms p95 trigger. |

### Pre-v1.0.0 closure checklist

- [x] M4 (admin HTTPS) merged. ✅
- [ ] M5 (keys-at-rest) merged.
- [ ] M6 (mTLS) merged.
- [ ] M7 (response controls) merged.
- [ ] M3 audit-write bench (T3.9) executed; report attached to closure issue.
- [ ] If trigger tripped, T3.10 async-batched landed.
- [ ] All verification gates closed with self-review (T6.2, T6.5, T6.7).
- [ ] Threat model (`docs/v2/threat-model.md`) reviewed and merged.
- [x] M4 runbook (`docs/v2/runbooks/m4-remote-management.md`) shipped. ✅
- [ ] Per-milestone runbooks (m5-sealed-secrets, m6-mtls-{onboarding,migration,revocation}, m7-response-controls) shipped.
- [ ] §7 changelog v1.0.0 entry written.

**Rough estimate: 4–6 working sessions of similar density to land v1.0.0** (was 5–7 before M4).

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

`src/daemon.rs::run` is the canonical entry. It validates the admin substrate triple (`listen.admin_socket` + `database.path` + `operator_credentials_path`), opens SQLite, builds the JSONL sink (if configured), constructs repos/auth/AdminService, spawns the agent listener + admin UDS + admin HTTPS (when enabled) + retention sweeper against a shared `ShutdownCoordinator`. The drain window awaits all four.

`AppState.config` is `Arc<ArcSwap<AppConfig>>`. The agent listener and AdminService share this snapshot.

### UDS HTTP client

`src/admin/uds_client.rs`: minimal hyper 1.x http1 over `tokio::net::UnixStream`. No hyperlocal dep, no pool. Each CLI call is a fresh connection.

### CLI Transport (M4)

`src/cli/client.rs::CliClient` is an enum-dispatched Transport: `Uds(UdsClient)` or `Https { reqwest::Client, base_url }`. `from_options(socket, admin_url, ca_bundle)` picks the right one. Precedence: `--admin-url` flag → `LOCKSMITH_ADMIN_URL` env → fall back to UDS. CA bundle: `--ca-bundle` / `LOCKSMITH_CA_BUNDLE` for self-signed/private-CA deployments.

### rustls CryptoProvider gotcha (M4)

rustls 0.23 requires an explicit process-level `CryptoProvider` when multiple are linked. Both server (axum-server) and client (reqwest with rustls-tls) pull providers transitively, so `agent_locksmith::admin::https::install_crypto_provider_once` installs `aws_lc_rs` once via `Once`. Daemon calls it from `bind_and_serve`; CLI calls it from `CliClient::from_options` when HTTPS is selected. **Don't remove this — silent failure mode is "client randomly cannot connect."**

### CLI exit codes (§4.7.2)

`0` ok | `1` generic | `2` usage | `3` auth | `4` not-found | `5` conflict.

### Config blocks (M3 + M4 additions)

```yaml
audit:                                                # M3
  retention_days: 90                                  # default
  sweep_interval_seconds: 3600                        # default (hourly)
  jsonl_path: "/var/log/..."                          # optional; absent = SQL only
  jsonl_max_bytes: 104857600                          # default 100 MiB
  jsonl_keep_files: 14                                # default

listen:
  admin_https:                                        # M4 — off by default
    enabled: true
    host: "0.0.0.0"                                   # default 127.0.0.1
    port: 9201                                        # default 9201
    cert_path: "/etc/locksmith/tls/server.crt"
    key_path: "/etc/locksmith/tls/server.key"
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
| M4 acceptance + ops | `docs/v2/runbooks/m4-remote-management.md` |

---

## 6. Resuming the next session

```bash
git fetch
git checkout develop
git pull

# Sanity check current state (170/170, clean lint).
cargo test --tests
cargo clippy --all-targets -- -D warnings
cargo fmt --check

# Branch off develop for M5 (recommended next).
git checkout -b m5/keys-at-rest
```

Workflow that has held through M1 + M2 + M3 + M4 (and should keep holding):

- **TDD per task** (`superpowers:test-driven-development`): failing test first; do not write production code without a failing test that justifies it.
- **Verification gates self-reviewed before merge**: closed so far T2.4 (schema), T2.9 (AgentAuthenticator), T2.12 (AdminService), T3.3 (retention). Coming: T6.2 + T6.5 (mTLS validator + authenticator), T6.7 (operator mTLS).
- **Conventional commits** with the milestone in the subject and `Closes #N` in the body. `Closes` only auto-closes on merges to default branch (which is `main`); since we merge to `develop`, manually `gh issue close` after each merge.
- **Issues filed proactively** (one per §6.2 task) with labels: `milestone:M{N}`, `component:*`, `layer:*`, `kind:*`, `risk:*`, plus per-requirement labels (`R-F12`, `UC-6`, `INF-25`).
- **No PRs required** for this project — direct merge to `develop` is the standing instruction.
- **Per-milestone close-out:** branch → tasks → tests/lint → commit/push → close issues → merge `--no-ff` to `develop` → bump version → tag `v0.{milestone+1}.0` → refresh this handoff. M2, M3, and M4 closure followed this exactly.

---

## 7. What success looks like for the next session

**Recommended target: M5 (keys-at-rest hardening).** ~7 tasks (5 M5 + 2 M2.x prereqs), no verification gate, ~1 session.

The big idea: an operator can deploy with the file-sealed `SecretBackend` and have **no upstream credential present in env vars or in any operator-readable config.** systemd unit ships hardened. Vault and AWS Secrets Manager get trait stubs (signatures + rustdoc) but no live impl in v0.6.0.

Concrete acceptance for the next session:
1. `tools[].auth.value` accepts a typed `SecretRef` enum: `Inline { value }` | `FromEnv { var }` | `FromFileSealed { path }`. Backward-compat shim accepts plain string as `Inline` per INF-24 (T2.17).
2. `SecretBackend` trait + `EnvBackend` impl formalized (T2.19); existing env-var path becomes a registered backend.
3. `FileSealedBackend` reads sealed file, decrypts via `systemd-creds` (or a configured key path), zeroizes on drop. Cache resolved value in memory; never hit disk twice (T5.1).
4. `dist/systemd/locksmith.service.template` ships with `NoNewPrivileges`, `ProtectSystem=strict`, `PrivateTmp`, dedicated `locksmith` user/group, minimal `ReadWritePaths` (T5.2).
5. `VaultBackend` + `AwsSecretsManagerBackend` *trait stubs* compile and have rustdoc explaining what an impl must do — but are NOT registered in dispatch (T5.3).
6. `docs/v2/threat-model.md` documents what at-rest hardening protects against (operator-readable config exposure, naïve memory dump) and what it doesn't (running-process memory, kernel exploits, root compromise) (T5.4).
7. Worked openclaw-hardened example at `dist/examples/sealed-secrets/` (T5.5).
8. `docs/v2/runbooks/m5-sealed-secrets.md` shipped.
9. End of session: merge → `v0.6.0` → tag.

If there's slack, **T3.9 (audit-write bench)** is the highest-value follow-up — it formally validates A-2 / INF-26 and is the pre-v1.0.0 closure-checklist gate that's most independent of M5 work. Adding the criterion-based bench harness once now pays off again at M6 (mTLS handshake bench).

After M5: M6 mTLS (the biggest milestone — likely two sessions split at the T6.5 / T6.7 gate boundary), then M7 response controls = v1.0.0.

The path to v1.0.0 from here fits in 4–6 sessions of similar density.

---

*End of handoff. Push back on anything that turns out wrong; update as you go.*
