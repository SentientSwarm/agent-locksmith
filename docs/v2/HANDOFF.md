# Handoff — Agent Locksmith v2 Implementation

**Last updated:** 2026-04-30
**Default working branch:** `develop` (M5 merged via `m5/keys-at-rest`)

This document is the cold-start context for the next session. Read top to bottom before touching code.

---

## 1. Where we are

| Branch | State | What's there |
|--------|-------|--------------|
| `main` | Stable | M0 implementation. CI passes. |
| `develop` | M5 closure | M0 + M1 + M2 + M3 + M4 + M5. Sealed credentials, hardened systemd unit, threat model. **Default working branch.** Tagged **v0.6.0**. |
| `m3/audit-pipeline`, `m4/admin-https`, `m5/keys-at-rest` | Merged | Kept for archaeology. |

### What's merged into `develop`

- v2 PRD + design (SoftwareDesign workflow, all 7 phases).
- **M1** (T1.1–T1.13): inference-ready hardening.
- **M2** (T2.1–T2.10, T2.12–T2.16, T2.22–T2.27): agent identity + admin substrate + locksmith CLI.
- **M3** (T3.1–T3.6, T3.8, T3.11): governance audit log.
- **M4** (T4.1–T4.6): admin HTTPS listener for remote management.
- **M5** (T2.17, T2.19, T5.1–T5.5): keys-at-rest hardening with file-sealed credentials.

### Test + lint state at M5 closure

- `cargo test --tests`: **193 / 193 pass** across 36 test binaries.
- `cargo clippy --all-targets -- -D warnings`: clean.
- `cargo fmt --check`: clean.

### M5 task progress (per SPEC §6.2)

| Task | Status | Notes |
|------|--------|-------|
| T2.17 — typed SecretRef enum | ✅ | `src/secret/mod.rs`. Custom Deserialize accepts legacy plain-string + tagged maps (FromEnv / FromFileSealed / FromVault / FromAwsSecretsManager). 8 parse tests. |
| T2.19 — SecretBackend trait + EnvBackend | ✅ | Async trait + `BackendError` + `SecretResolver` dispatcher. EnvBackend handles LegacyString (with one-shot INF-24 deprecation warning) and FromEnv. 6 tests. |
| T5.1 — FileSealedBackend | ✅ | Reads systemd-creds-decrypted file; rejects group/world-readable; caches; zeroizes on Drop. 5 tests. |
| T5.2 — systemd hardened unit template | ✅ | `dist/systemd/locksmith.service.template` with NoNewPrivileges, ProtectSystem=strict, MemoryDenyWriteExecute, dedicated user, etc. |
| T5.3 — Vault + AWS stubs | ✅ | `src/secret/vault.rs` + `src/secret/aws.rs`. Constructible; `resolve()` → `NotImplemented`. 2 stub tests. |
| T5.4 — threat model | ✅ | `docs/v2/threat-model.md`. 11-row mitigations matrix mapping threats to milestones. |
| T5.5 — sealed-secrets worked example | ✅ | `dist/examples/sealed-secrets/{README.md,locksmith.service,config.yaml,seal-credential.sh}`. |
| M5 integration | ✅ | `tool.auth.value: SecretRef`. Daemon resolves at startup; proxy hot path reads from `resolved_creds` map. Degraded mode for failed tools (per INF-4 / Q-17). 2 daemon-driven integration tests. |
| M5 runbook | ✅ | `docs/v2/runbooks/m5-sealed-secrets.md`. |

### Verification gates closed

| Task | Status |
|------|--------|
| T2.4 schema | Closed in M2 |
| T2.9 AgentAuthenticator | Closed in M2 |
| T2.12 AdminService | Closed in M2 |
| T3.3 retention worker | Closed in M3 |

M4 + M5 had no verification gates (low-risk per SPEC §6.2). Coming gates: **T6.2** + **T6.5** (mTLS validator + authenticator), **T6.7** (operator mTLS).

---

## 2. M5 acceptance demo

The M5 contract — *"operator can deploy with the file-sealed backend and have no upstream credential present in env vars or in any operator-readable config"* — is met. Full walk-through is in `dist/examples/sealed-secrets/README.md`.

```bash
# (1) Seal the credential — plaintext never touches disk.
sudo bash dist/examples/sealed-secrets/seal-credential.sh \
    openai_token /etc/locksmith/credentials/openai.enc

# (2) Install the hardened unit + sealed-secrets-aware config.
sudo install -m 0644 dist/examples/sealed-secrets/locksmith.service \
    /etc/systemd/system/locksmith.service
sudo install -m 0644 -o locksmith -g locksmith \
    dist/examples/sealed-secrets/config.yaml \
    /etc/locksmith/config.yaml
sudo systemctl daemon-reload && sudo systemctl enable --now locksmith

# (3) Verify resolution.
journalctl -u locksmith --since "1 min ago" | grep file-sealed
# Expect: "file-sealed credential resolved" with the path

# (4) Verify the threat boundary as an unprivileged user.
cat /run/credentials/locksmith/openai_token  # → permission denied
cat /etc/locksmith/credentials/openai.enc    # → encrypted bytes; useless without TPM/master key

# (5) Rotate.
sudo bash dist/examples/sealed-secrets/seal-credential.sh \
    openai_token /etc/locksmith/credentials/openai.enc
sudo systemctl restart locksmith
```

The previous milestone's M4 demo (admin HTTPS) is in `docs/v2/runbooks/m4-remote-management.md` §3.

## 2.1 M4 acceptance demo (kept for reference)

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

Two milestones remain (M6, M7), plus M2.x / M3.x carry-overs that can land any time.

### Milestone walk to v1.0.0

| Milestone | Version | Tasks | Goal | Verification gates |
|-----------|---------|-------|------|--------------------|
| ~~M4~~ | ~~v0.5.0~~ | ~~T4.1–T4.6~~ | ~~Admin HTTPS for remote management.~~ | ~~—~~ ✅ Closed |
| ~~M5~~ | ~~v0.6.0~~ | ~~T2.17 + T2.19 + T5.1–T5.5~~ | ~~Keys-at-rest hardening.~~ | ~~—~~ ✅ Closed |
| **M6** | v0.7.0 | T6.1–T6.11 (~11; biggest) | mTLS for agents + operators. CRL fetcher, local emergency blocklist, bootstrap-only listener (C-4), `auth_mode: bearer | mtls | both`. | **T6.2 + T6.5** (MtlsValidator + MtlsAuthenticator), **T6.7** (operator mTLS) |
| **M7** | v1.0.0 | T7.1–T7.4 (~4) | Per-tool response controls: max_size_bytes, content_type_allowlist, regex redaction. Streaming preserved (only total-size cap applies). | — |

### M6 — mTLS (next session — likely 2 sessions)

**Goal:** Cryptographic identity for agents AND operators. Two-session split recommended at the T6.5 / T6.7 gate boundary.

**Session A — Agent-side mTLS (T6.1–T6.5 + gate):**
- T6.1 deps (`x509-parser`; `rcgen` already present as dev-dep from M4)
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

**Schema change anticipated (M6):** `agents.cert_identity` column for the M6.5 lookup. Plan for a second forward-only migration `migrations/0002_mtls.sql`. The schema change touches the M2 spine — **review the M2 schema-gate notes in SPEC §6.4.1 before writing the migration.**


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
| T2.17 typed `SecretRef` | ✅ Landed in M5. |
| T2.18 field-scoped `${VAR}` | M0 textual expander handles dominant case via `LegacyString` variant. |
| T2.19 `SecretBackend` trait + `EnvBackend` | ✅ Landed in M5. |
| T2.20 hot reload + listener-shape carve-out | M0 ArcSwap is in place; full reload logic is here. The M4 listener-shape fields (`admin_https.{cert_path,key_path,host,port,enabled}`) and M5 sealed-credential paths feed in here when reload lands. M6 may surface this. |
| T2.21 startup-check sequencing (INF-2) | Daemon already fail-fast on the path that matters. |
| T2.27 `locksmith config reload/show` | Useful but not critical for M6. |
| T2.28/T2.29 bench subcommands | A-1 verification; useful, not blocking. |

**M3.x:**
| Task | Notes |
|------|-------|
| T3.7 `locksmith audit tail` | Streaming follow; needs SSE endpoint. |
| T3.9 audit-write bench | A-2 / INF-26 validation; **must run before v1.0.0 cut**. |
| T3.10 conditional async-batched | Only if T3.9 trips the >5ms p95 trigger. |

### Pre-v1.0.0 closure checklist

- [x] M4 (admin HTTPS) merged. ✅
- [x] M5 (keys-at-rest) merged. ✅
- [ ] M6 (mTLS) merged.
- [ ] M7 (response controls) merged.
- [ ] M3 audit-write bench (T3.9) executed; report attached to closure issue.
- [ ] If trigger tripped, T3.10 async-batched landed.
- [ ] All verification gates closed with self-review (T6.2, T6.5, T6.7).
- [x] Threat model (`docs/v2/threat-model.md`) reviewed and merged. ✅
- [x] M4 runbook (`docs/v2/runbooks/m4-remote-management.md`) shipped. ✅
- [x] M5 runbook (`docs/v2/runbooks/m5-sealed-secrets.md`) shipped. ✅
- [ ] Per-milestone runbooks (m6-mtls-{onboarding,migration,revocation}, m7-response-controls) shipped.
- [ ] §7 changelog v1.0.0 entry written.

**Rough estimate: 3–4 working sessions of similar density to land v1.0.0** (was 4–6 before M5).

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

`src/daemon.rs::run` is the canonical entry. It validates the admin substrate triple (`listen.admin_socket` + `database.path` + `operator_credentials_path`), opens SQLite, builds the JSONL sink (if configured), constructs the M5 `SecretResolver` with `FileSealedBackend`, walks `tools[].auth.value` through it to produce the resolved-creds map, constructs repos/auth/AdminService, spawns the agent listener + admin UDS + admin HTTPS (when enabled) + retention sweeper against a shared `ShutdownCoordinator`. The drain window awaits all four.

`AppState.config` is `Arc<ArcSwap<AppConfig>>`. `AppState.resolved_creds` is `Arc<ArcSwap<HashMap<String, SecretString>>>`. Both are shared between the agent listener and AdminService so hot reload (when it lands in T2.20) updates both surfaces atomically.

### UDS HTTP client

`src/admin/uds_client.rs`: minimal hyper 1.x http1 over `tokio::net::UnixStream`. No hyperlocal dep, no pool. Each CLI call is a fresh connection.

### CLI Transport (M4)

`src/cli/client.rs::CliClient` is an enum-dispatched Transport: `Uds(UdsClient)` or `Https { reqwest::Client, base_url }`. `from_options(socket, admin_url, ca_bundle)` picks the right one. Precedence: `--admin-url` flag → `LOCKSMITH_ADMIN_URL` env → fall back to UDS. CA bundle: `--ca-bundle` / `LOCKSMITH_CA_BUNDLE` for self-signed/private-CA deployments.

### SecretBackend dispatch (M5)

`src/secret/backend.rs::SecretResolver` is a composite dispatcher: `EnvBackend` always present; `FileSealedBackend` optional (daemon wires it; sync test path skips it); Vault/AWS variants → `NotImplemented`. The async `SecretBackend::resolve(SecretRef)` is the daemon's eager-resolve entrypoint. The sync sibling `EnvBackend::resolve_sync` exists for non-async test paths (build_app_with_audit's eager resolution).

**Don't store unresolved SecretRefs in AppState** — they're config-shape only. The proxy hot path reads `AppState.resolved_creds`, which is the post-resolution `HashMap<tool_name, SecretString>`. Tools whose credentials fail to resolve are absent from the map (degraded mode per INF-4).

### Sealed-secrets threat boundary (M5)

Locksmith does NOT do AEAD itself. systemd-creds (`LoadCredentialEncrypted=`) decrypts blobs at service start into `/run/credentials/locksmith/$NAME` (mode 0400, owned by locksmith). Locksmith reads the file. The threat model (`docs/v2/threat-model.md` §1.1) spells this out: the trust boundary is "anything readable by the locksmith uid is already trusted". Operators wanting to defend against compromised-locksmith-uid need the post-v2 HSM path.

### rustls CryptoProvider gotcha (M4)

rustls 0.23 requires an explicit process-level `CryptoProvider` when multiple are linked. Both server (axum-server) and client (reqwest with rustls-tls) pull providers transitively, so `agent_locksmith::admin::https::install_crypto_provider_once` installs `aws_lc_rs` once via `Once`. Daemon calls it from `bind_and_serve`; CLI calls it from `CliClient::from_options` when HTTPS is selected. **Don't remove this — silent failure mode is "client randomly cannot connect."**

### CLI exit codes (§4.7.2)

`0` ok | `1` generic | `2` usage | `3` auth | `4` not-found | `5` conflict.

### Config blocks (M3 + M4 + M5 additions)

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

# tools[].auth.value (M5) — accepts both the legacy plain-string form
# (M0/M1 backward compat with INF-24 deprecation warning) AND tagged
# typed forms:
tools:
  - name: legacy
    auth:
      header: "authorization"
      value: "Bearer ${TOKEN}"                        # legacy, still works
  - name: env
    auth:
      header: "authorization"
      value:
        from_env:
          var: API_KEY
          prefix: "Bearer "                           # optional
  - name: sealed
    auth:
      header: "authorization"
      value:
        from_file_sealed:
          path: "/run/credentials/locksmith/api_key"  # systemd-creds drop path
  # from_vault and from_aws_secrets_manager are stubs in v0.6.0 (NotImplemented)
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
| M5 acceptance + ops | `docs/v2/runbooks/m5-sealed-secrets.md` |
| Threat model | `docs/v2/threat-model.md` |
| Sealed-secrets worked example | `dist/examples/sealed-secrets/README.md` |
| Hardened systemd template | `dist/systemd/locksmith.service.template` |

---

## 6. Resuming the next session

```bash
git fetch
git checkout develop
git pull

# Sanity check current state (193/193, clean lint).
cargo test --tests
cargo clippy --all-targets -- -D warnings
cargo fmt --check

# Branch off develop for M6 — likely two sessions; first one stops at the
# T6.5 verification gate.
git checkout -b m6/mtls-agent-side
```

Workflow that has held through M1 + M2 + M3 + M4 + M5 (and should keep holding):

- **TDD per task** (`superpowers:test-driven-development`): failing test first; do not write production code without a failing test that justifies it.
- **Verification gates self-reviewed before merge**: closed so far T2.4 (schema), T2.9 (AgentAuthenticator), T2.12 (AdminService), T3.3 (retention). Coming: T6.2 + T6.5 (mTLS validator + authenticator), T6.7 (operator mTLS).
- **Conventional commits** with the milestone in the subject and `Closes #N` in the body. `Closes` only auto-closes on merges to default branch (which is `main`); since we merge to `develop`, manually `gh issue close` after each merge.
- **Issues filed proactively** (one per §6.2 task) with labels: `milestone:M{N}`, `component:*`, `layer:*`, `kind:*`, `risk:*`, plus per-requirement labels (`R-F12`, `UC-6`, `INF-25`).
- **No PRs required** for this project — direct merge to `develop` is the standing instruction.
- **Per-milestone close-out:** branch → tasks → tests/lint → commit/push → close issues → merge `--no-ff` to `develop` → bump version → tag `v0.{milestone+1}.0` → refresh this handoff. M2, M3, M4, and M5 closure followed this exactly.

---

## 7. What success looks like for the next session

**Recommended target: M6 Session A (agent-side mTLS — T6.1 through T6.5 + the T6.5 verification gate).** Five tasks ending at a verification gate; ~1 session.

The big idea: agents present a client cert at the TLS handshake; Locksmith validates the cert against a configured CA bundle, checks the CRL, checks the local emergency blocklist, extracts the identity (CN / SAN_DNS / SAN_URI), and maps that identity to an agent record in the DB. `auth_method=mtls` audit follows in Session B.

Concrete acceptance for Session A:
1. New schema migration `migrations/0002_mtls.sql` adds `agents.cert_identity TEXT NULL` with a unique index. **Re-read SPEC §6.4.1 schema-gate notes before writing the DDL.**
2. `AgentRepository.get_by_cert_identity(&str) -> Option<AgentRecord>` lookup added.
3. `MtlsValidator` (T6.2) — chain validation against CA bundle, expiration, identity extraction. **Verification gate**: full review of cert parsing + identity extraction + edge cases (multiple SAN entries, CN fallback, expired-but-not-yet, malformed cert).
4. CRL fetcher (T6.3): periodic background task; metrics `mtls_crl_refresh_failures_total` + `mtls_crl_age_seconds`; stale CRL still validates per SPEC §6.2.
5. Local emergency blocklist (T6.4): file at `mtls.blocklist_path`, one serial per line, hot reload on file change.
6. `MtlsAuthenticator` (T6.5) — implements `AgentAuthenticator`; calls `MtlsValidator` then `AgentRepository.get_by_cert_identity`. **Verification gate**: full review of the auth flow (per SPEC §6.4.1).
7. `tests/mtls_validator_test.rs` + `tests/mtls_authenticator_test.rs` cover happy + sad paths using `rcgen`-minted fixtures.
8. End of session: branch stays open (do NOT merge yet — Session B closes the milestone). Land Session A's work on `m6/mtls-agent-side`. Refresh handoff to point at Session B.

If there's slack between gates, **T3.9 (audit-write bench)** is the highest-value follow-up — it formally validates A-2 / INF-26 and is the pre-v1.0.0 closure-checklist gate that's most independent of M6 work.

After M6 Session A → M6 Session B (auth_mode + operator mTLS + tooling, T6.6–T6.11 + T6.7 gate), then M7 response controls = v1.0.0.

The path to v1.0.0 from here fits in 3–4 sessions of similar density.

---

*End of handoff. Push back on anything that turns out wrong; update as you go.*
