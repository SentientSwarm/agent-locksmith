# Handoff — Agent Locksmith v2 Implementation

**Last updated:** 2026-04-30
**Default working branch:** `develop` (M6 merged via `m6/mtls-agent-side`)

This document is the cold-start context for the next session. Read top to bottom before touching code.

---

## 1. Where we are

| Branch | State | What's there |
|--------|-------|--------------|
| `main` | Stable | M0 implementation. CI passes. |
| `develop` | M6 closure | M0 + M1 + M2 + M3 + M4 + M5 + M6. mTLS validator + CRL + blocklist + authenticator + bootstrap-only listener + operator cert mapping. **Default working branch.** Tagged **v0.7.0**. |
| `m3/audit-pipeline`, `m4/admin-https`, `m5/keys-at-rest`, `m6/mtls-agent-side` | Merged | Kept for archaeology. |

### What's merged into `develop`

- v2 PRD + design (SoftwareDesign workflow, all 7 phases).
- **M1** (T1.1–T1.13): inference-ready hardening.
- **M2** (T2.1–T2.10, T2.12–T2.16, T2.22–T2.27): agent identity + admin substrate + locksmith CLI.
- **M3** (T3.1–T3.6, T3.8, T3.11): governance audit log.
- **M4** (T4.1–T4.6): admin HTTPS listener for remote management.
- **M5** (T2.17, T2.19, T5.1–T5.5): keys-at-rest hardening with file-sealed credentials.
- **M6** (T6.1–T6.11): mTLS — validator, CRL fetcher, blocklist, authenticator, bootstrap-only listener, operator cert mapping, CLI mtls subcommands, smallstep example, 3 mTLS runbooks.

### Test + lint state at M6 closure

- `cargo test --tests`: **224 / 224 pass** across 41 test binaries.
- `cargo clippy --all-targets -- -D warnings`: clean.
- `cargo fmt --check`: clean.

### M6 task progress (per SPEC §6.2)

| Task | Status | Notes |
|------|--------|-------|
| T6.1 — deps | ✅ | x509-parser, pem, rustls-webpki, time (dev). |
| T6.2 GATE — MtlsValidator | ✅ | webpki chain + identity extraction (CN→SAN_DNS→SAN_URI). 8 tests. |
| T6.3 — CRL fetcher | ✅ | CrlStore + apply_pem + refresh_once. Stale-but-up. 4 tests. |
| T6.4 — local blocklist | ✅ | File-backed; mtime-driven reload. 3 tests. |
| T6.5 GATE — MtlsAuthenticator | ✅ | Implements `authenticate_cert(der)`; revoked agents filtered. 4 tests. |
| T6.6 — auth_mode | ✅ | Bearer/Mtls/Both config + 4 parse tests. **Bind-path wiring deferred to v0.7.x** (see §3 below). |
| T6.7 GATE — operator mTLS | ✅ | OperatorRecord.cert_identity + authenticate_cert_identity. 3 tests. |
| T6.8 — bootstrap-only listener | ✅ | C-4 single-endpoint TLS listener. 2 tests. |
| T6.9 — `locksmith mtls` CLI | ✅ | revoke / list-blocklist / crl-status. Subprocess test. |
| T6.10 — auth_method audit | ✅ | Auto-fill in AdminService.audit + proxy hot path. 2 tests. |
| T6.11 — smallstep example + 3 runbooks | ✅ | dist/examples/smallstep/ + onboarding/migration/revocation runbooks. |

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

M4 + M5 had no verification gates (low-risk per SPEC §6.2). M6 closed three gates this session: T6.2 (MtlsValidator), T6.5 (MtlsAuthenticator), T6.7 (operator mTLS).

**Remaining gates: none.** M7 has no verification gate per SPEC §6.2.

---

## 2. M6 acceptance demo

Smallstep deployment per `dist/examples/smallstep/README.md`. Fast version:

```bash
# Provision agent CA bundle
sudo install -m 0644 -o locksmith -g locksmith \
    agents-ca.crt /etc/locksmith/agents-ca.crt

# Daemon config (auth_mode=both during migration; mtls once fleet rotates)
cat >> /etc/locksmith/config.yaml <<EOF
listen:
  auth_mode: both
  mtls:
    ca_bundle_path: "/etc/locksmith/agents-ca.crt"
    crl_url: "https://step-ca.example.com/crl"
    crl_refresh_interval_seconds: 600
    blocklist_path: "/etc/locksmith/blocklist"
  bootstrap_only:
    enabled: true
    host: "0.0.0.0"
    port: 9202
    cert_path: "/etc/locksmith/tls/bootstrap.crt"
    key_path: "/etc/locksmith/tls/bootstrap.key"
EOF
sudo systemctl restart locksmith

# Onboard an agent through the bootstrap-only listener (no operator creds needed)
TOKEN=$(locksmith bootstrap mint --single-use --format json | jq -r .token)
curl -X POST https://locksmith.example.com:9202/admin/agent/register \
    --cacert /etc/locksmith/agents-ca.crt \
    -H 'content-type: application/json' \
    -d "$(jq -n --arg t "$TOKEN" '{bootstrap_token: $t, name: "agent-7"}')"

# Bind cert_identity (via the AgentRepository helper; CLI wrapper lands v0.7.x)
# UPDATE agents SET cert_identity = 'agent-7' WHERE public_id = '<public_id>';

# Emergency revoke a serial (effective within 30s — blocklist watcher)
sudo locksmith mtls revoke <SERIAL_HEX> \
    --blocklist-path /etc/locksmith/blocklist \
    --reason "incident 2026-04-30"

# Verify mtls auth_method appears in audit
locksmith audit query --event-class security --limit 5 --format json
```

Full operational guide: `docs/v2/runbooks/m6-mtls-onboarding.md`. Migration recipe: `docs/v2/runbooks/m6-mtls-migration.md`. Incident response: `docs/v2/runbooks/m6-mtls-revocation.md`.

## 2.1 M5 acceptance demo (kept for reference)

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

One milestone remains (M7), plus the v0.7.x agent-listener bind-path follow-up and M2.x / M3.x carry-overs.

### Milestone walk to v1.0.0

| Milestone | Version | Tasks | Goal | Verification gates |
|-----------|---------|-------|------|--------------------|
| ~~M4~~ | ~~v0.5.0~~ | ~~T4.1–T4.6~~ | ~~Admin HTTPS for remote management.~~ | ~~—~~ ✅ Closed |
| ~~M5~~ | ~~v0.6.0~~ | ~~T2.17 + T2.19 + T5.1–T5.5~~ | ~~Keys-at-rest hardening.~~ | ~~—~~ ✅ Closed |
| ~~M6~~ | ~~v0.7.0~~ | ~~T6.1–T6.11~~ | ~~mTLS support.~~ | ~~T6.2, T6.5, T6.7~~ ✅ All closed |
| **M7** | v1.0.0 | T7.1–T7.4 (~4) | Per-tool response controls: max_size_bytes, content_type_allowlist, regex redaction. Streaming preserved (only total-size cap applies). | — |

### v0.7.x — agent-listener mTLS bind path (deferred from M6)

Validator + authenticator + CRL + blocklist + audit threading + bootstrap-only listener + operator cert mapping all landed in v0.7.0 as production-ready code with full test coverage. The remaining piece is the agent-listener TLS bind that requires client certs at the handshake:

- Replace the agent listener's plain TCP bind with `axum_server::bind_rustls` when `auth_mode` is `mtls` or `both`.
- Configure the rustls `ServerConfig` with a `ClientCertVerifier` (rustls's `WebPkiClientVerifier::builder` against the `mtls.ca_bundle_path`).
- Inject the peer cert DER into the request via an axum extractor that reads from rustls's connection state.
- Middleware switches on `auth_mode` to call `MtlsAuthenticator::authenticate_cert` (with bearer fallback under `both`).

This is ~1 focused session; no new gates. Recommend landing it as `m6.1/agent-listener-mtls` before starting M7 if mTLS is a release-blocker for the user's deployment, or after M7 if not.

### M7 — Response controls (next session — final milestone)

**Goal:** Per-tool max_size_bytes, content_type_allowlist, regex redaction. Streaming first-byte latency must stay ≤100ms (R-N6).

| Task | Summary |
|------|---------|
| T7.1 | `tools[].response: { max_size_bytes, content_type_allowlist, redaction_patterns }` |
| T7.2 | `ResponseControls.apply` for non-streaming (read body, check content-type, apply redaction) |
| T7.3 | Streaming wrapper: byte-counter `Stream` adapter that emits truncation marker on cap-exceeded |
| T7.4 | Audit events: `response_redaction` (with hash of match, NOT cleartext) and `response_size_exceeded` |

**Acceptance criterion:** rerun M1 streaming tests with response controls enabled — first-byte latency must still be ≤100ms.


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
- [x] M6 (mTLS) merged. ✅
- [ ] M7 (response controls) merged.
- [ ] v0.7.x — agent-listener mTLS bind path (T6.6 wiring follow-up).
- [ ] M3 audit-write bench (T3.9) executed; report attached to closure issue.
- [ ] If trigger tripped, T3.10 async-batched landed.
- [x] All verification gates closed with self-review (T6.2, T6.5, T6.7). ✅
- [x] Threat model (`docs/v2/threat-model.md`) reviewed and merged. ✅
- [x] M4 runbook (`docs/v2/runbooks/m4-remote-management.md`) shipped. ✅
- [x] M5 runbook (`docs/v2/runbooks/m5-sealed-secrets.md`) shipped. ✅
- [x] M6 runbooks (`m6-mtls-onboarding.md`, `m6-mtls-migration.md`, `m6-mtls-revocation.md`) shipped. ✅
- [ ] M7 runbook (`docs/v2/runbooks/m7-response-controls.md`) shipped.
- [ ] §7 changelog v1.0.0 entry written.

**Rough estimate: 1–2 working sessions of similar density to land v1.0.0** (was 3–4 before M6).

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
| M6 onboarding | `docs/v2/runbooks/m6-mtls-onboarding.md` |
| M6 migration recipe | `docs/v2/runbooks/m6-mtls-migration.md` |
| M6 revocation playbook | `docs/v2/runbooks/m6-mtls-revocation.md` |
| smallstep / step-ca example | `dist/examples/smallstep/README.md` |

---

## 6. Resuming the next session

```bash
git fetch
git checkout develop
git pull

# Sanity check current state (224/224, clean lint).
cargo test --tests
cargo clippy --all-targets -- -D warnings
cargo fmt --check

# Branch off develop for M7 — final milestone, no verification gate.
git checkout -b m7/response-controls

# OR — close the M6 follow-up first if mTLS is a release blocker:
# git checkout -b m6.1/agent-listener-mtls
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

**Recommended target: M7 (per-tool response controls — final milestone).** Four tasks, no verification gate. ~1 session.

The big idea: operators bound the response surface per-tool. A misbehaving upstream that streams an unbounded body, returns the wrong content-type, or leaks a secret in the response can be capped/rejected/redacted before the agent sees it. Streaming flows from M1 must stay intact: only total-size cap applies, and first-byte latency must remain ≤100ms (R-N6).

Concrete acceptance for the next session:
1. `tools[].response: { max_size_bytes, content_type_allowlist, redaction_patterns }` parses (T7.1).
2. `ResponseControls.apply` for non-streaming responses: read body subject to `max_size_bytes`; reject content-types not in allowlist; apply regex `redaction_patterns` (T7.2).
3. Streaming wrapper: a `Stream` adapter that counts bytes and emits a truncation marker on cap-exceeded; integrated into the proxy streaming path (T7.3).
4. Audit events: `response_redaction` (with `pattern_id` + `matches` count + hashed-match identifier — NEVER cleartext) and `response_size_exceeded` (T7.4).
5. Regression: rerun M1 streaming tests (`tests/streaming_passthrough_test.rs`) with response controls enabled on the test tool. First-byte latency still ≤100ms.
6. `tests/response_controls_size_test.rs`, `tests/response_controls_content_type_test.rs`, `tests/response_controls_redaction_test.rs` cover the three control modes.
7. `docs/v2/runbooks/m7-response-controls.md` shipped.
8. End of session: merge → `v1.0.0` → tag.

**Alternative target if mTLS is a release blocker:** the v0.7.x agent-listener bind path. Validator/authenticator already landed; this session wires the rustls server config + peer-cert extractor + middleware switch on `auth_mode`. ~1 session, no new gates.

**v1.0.0 closure tasks** (do AFTER M7 lands):
- §7 changelog entry summarizing v0.2.0 → v1.0.0.
- Pre-v1.0.0 closure checklist sweep (see §3 above).
- M3 audit-write bench (T3.9) execution; report → closure issue.
- Optional: T3.10 async-batched if T3.9 trips the >5ms p95 trigger.

The path to v1.0.0 from here fits in 1–2 sessions of similar density. M7 is the last milestone; everything after is closure-checklist housekeeping.

---

*End of handoff. Push back on anything that turns out wrong; update as you go.*
