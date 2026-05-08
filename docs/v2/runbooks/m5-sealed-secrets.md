# M5 — Keys-at-Rest Hardening Runbook

**Audience:** operators deploying Locksmith with sealed credentials, and engineers verifying the M5 acceptance contract before merging to `develop`.

**Covers:** the typed `SecretRef` enum, the `SecretBackend` trait + `EnvBackend` + `FileSealedBackend`, the systemd unit template, the worked sealed-secrets example, and the threat-model boundary that justifies all of the above.

---

## 1. M5 acceptance checklist

| Criterion | Source | Verified by |
|-----------|--------|-------------|
| `tool.auth.value` accepts typed `from_env`, `from_file_sealed`, `from_vault`, `from_aws_secrets_manager` | T2.17 | `tests/secret_ref_parse_test.rs` (8 tests) |
| Legacy plain-string `value: "Bearer ${TOKEN}"` still parses (INF-24 backward compat) | T2.17 | `tests/secret_ref_parse_test.rs::legacy_plain_string_parses_as_legacy_variant` |
| `EnvBackend` resolves `FromEnv` (with optional prefix) and `LegacyString` (with `${VAR}` expansion) | T2.19 | `tests/secret_backend_env_test.rs` (6 tests) |
| Missing env var on `FromEnv` returns `BackendError::Missing(name)` | T2.19 | `tests/secret_backend_env_test.rs::from_env_missing_var_returns_missing` |
| `FileSealedBackend` reads chmod-0600 credential, strips trailing newline | T5.1 | `tests/secret_backend_file_sealed_test.rs::file_sealed_happy_path_reads_and_strips_trailing_newline` |
| `FileSealedBackend` rejects world/group-readable files | T5.1 | `tests/secret_backend_file_sealed_test.rs::file_sealed_rejects_world_readable_file` |
| `FileSealedBackend` caches first read; subsequent calls don't re-hit disk | T5.1 | `tests/secret_backend_file_sealed_test.rs::file_sealed_caches_after_first_read` |
| Vault + AWS backends compile as stubs returning `NotImplemented` | T5.3 | `tests/secret_backend_stubs_test.rs` (2 tests) |
| Daemon resolves `from_file_sealed:` credential at startup; proxy hot path injects it on requests | M5 integration | `tests/secret_proxy_integration_test.rs::from_file_sealed_credential_reaches_proxy_hot_path` |
| Tools whose credential fails to resolve degrade quietly (don't take the daemon down; absent from `/tools`) | INF-4 / Q-17 | `tests/secret_proxy_integration_test.rs::missing_sealed_file_degrades_tool_quietly` |
| systemd unit ships with hardening directives | T5.2 | `dist/systemd/locksmith.service.template` (review against `docs/v2/threat-model.md` §4 mitigations) |
| Threat model documented | T5.4 | `docs/v2/threat-model.md` |
| Worked sealed-secrets example shipped | T5.5 | `dist/examples/sealed-secrets/{README.md,locksmith.service,config.yaml,seal-credential.sh}` |
| `cargo clippy --all-targets -- -D warnings` clean | engineering std | local CI mirror |
| `cargo fmt --check` clean | engineering std | local CI mirror |

---

## 2. Choosing a credential resolution path

| Path | Use when | Caveats |
|------|----------|---------|
| `value: "Bearer ${TOKEN}"` (legacy) | M0/M1 deployments mid-migration | One-shot deprecation warning per process; migrate to `from_env` |
| `value: { from_env: { var: TOKEN } }` | Container / dev / single-tenant boxes | Plaintext in env; visible to anyone who can `cat /proc/$pid/environ` |
| `value: { from_file_sealed: { path: ... } }` | Production | Requires systemd-creds (or operator-managed tmpfs); recommended default |
| `value: { from_vault: ... }` | Post-v2 only — stub today | `BackendError::NotImplemented`; live impl tracked at #71 |
| `value: { from_aws_secrets_manager: ... }` | Post-v2 only — stub today | Same; tracked at #72 |
| `value: { from_file_sealed: ... }` + 1Password CLI | Production (1Password fleets) | See §3.1 below; works today, no Locksmith change. Live `from_1password:` backend tracked at #80 |

The acceptance bar for v0.6.0 production deployments is `from_file_sealed`. See §3 for the systemd-creds recipe and §3.1 for the 1Password operator-side variant.

---

## 3. Sealed-secrets recipe (recommended production)

Full walk-through is in `dist/examples/sealed-secrets/README.md`. Quick version:

```bash
# 1. Seal the credential.
sudo bash dist/examples/sealed-secrets/seal-credential.sh \
    openai_token /etc/locksmith/credentials/openai.enc

# 2. Install the unit and config.
sudo install -m 0644 dist/examples/sealed-secrets/locksmith.service \
    /etc/systemd/system/locksmith.service
sudo install -m 0644 -o locksmith -g locksmith \
    dist/examples/sealed-secrets/config.yaml \
    /etc/locksmith/config.yaml
sudo systemctl daemon-reload

# 3. Start the daemon.
sudo systemctl enable --now locksmith

# 4. Verify resolution.
journalctl -u locksmith --since "1 min ago" | grep file-sealed
# Expect: "file-sealed credential resolved" with the path
```

The encrypted blob (`openai.enc`) is bound to the host's TPM (or to `/var/lib/systemd/credential.secret`); a stolen drive doesn't decrypt elsewhere. The decrypted plaintext lives only at `/run/credentials/locksmith/openai_token` (tmpfs, mode 0400, owned by `locksmith`) — readable only by the daemon (and root).

---

## 3.1 1Password variant (operator-side resolution)

For fleets standardized on 1Password, the same `from_file_sealed:` mechanism works without a live `OnePasswordBackend` impl (#80). The pattern: a systemd `ExecStartPre=` step runs the 1Password CLI to materialize the secret at the path Locksmith reads. This satisfies the M5 acceptance bar (no plaintext in operator-readable config; plaintext lives only at a chmod-0400 tmpfs path) and works **today** with zero Locksmith change.

### Setup

```bash
# 1. Provision a 1Password service-account token (out-of-band) and seal it
#    via systemd-creds so the unit can authenticate non-interactively.
sudo bash dist/examples/sealed-secrets/seal-credential.sh \
    op_service_account_token /etc/locksmith/credentials/op_token.enc

# 2. Reference the secret in Locksmith config the same way as systemd-creds.
#    `from_file_sealed.path` points at /run/credentials/locksmith/openai_token
#    — the file the systemd unit will materialize at start.
```

`config.yaml`:

```yaml
tools:
  - name: openai
    upstream: "https://api.openai.com"
    auth:
      header: "authorization"
      value:
        from_file_sealed:
          path: "/run/credentials/locksmith/openai_token"
```

### systemd unit additions

```ini
[Service]
# Existing M5 directives ...
LoadCredentialEncrypted=op_token:/etc/locksmith/credentials/op_token.enc

# Materialize the 1Password-resolved secret BEFORE the daemon starts.
# `op` reads the service-account token from $OP_SERVICE_ACCOUNT_TOKEN; we
# point it at the systemd-creds-decrypted file. The result is written to
# /run/credentials/locksmith/openai_token (tmpfs, mode 0400, locksmith-owned).
ExecStartPre=/bin/bash -c '\
    install -d -m 0700 -o locksmith -g locksmith /run/credentials/locksmith && \
    OP_SERVICE_ACCOUNT_TOKEN="$$(cat ${CREDENTIALS_DIRECTORY}/op_token)" \
    /usr/local/bin/op read "op://Engineering/OpenAI Production/credential" \
    > /run/credentials/locksmith/openai_token && \
    chown locksmith:locksmith /run/credentials/locksmith/openai_token && \
    chmod 0400 /run/credentials/locksmith/openai_token'
```

### Threat boundary

Same as the §3 systemd-creds path: an unprivileged user cannot read `/run/credentials/locksmith/openai_token` (mode 0400, locksmith-owned). The 1Password service-account token itself is sealed by systemd-creds (TPM-bound when available), so a stolen disk doesn't compromise it. The decrypted secret lives in tmpfs only.

### Rotation

Update the secret in 1Password and restart Locksmith — `ExecStartPre=` re-runs `op read` and pulls the new value. No reseal needed for the secrets themselves; the service-account token is reseal-on-rotation just like any other systemd-creds blob.

```bash
sudo systemctl restart locksmith
```

### When to migrate to the live `OnePasswordBackend`

Track #80. Reasons to switch:
- You want Locksmith to refresh secrets without a restart (post-v2 hot-reload, T2.20 #70).
- You want `op read` failures to surface as Locksmith audit rows rather than systemd unit start failures.
- You want to remove the `ExecStartPre=` line from your unit (cleaner unit, fewer moving parts).

Until then, this section is the recommended path. It composes cleanly with the existing M5 acceptance contract.

---

## 4. Rotation

Rotation is **restart-on-reseal** in v0.6.0. Hot-reload of credentials is a future enhancement.

```bash
# Reseal with the new value.
sudo bash dist/examples/sealed-secrets/seal-credential.sh \
    openai_token /etc/locksmith/credentials/openai.enc

# Restart so the daemon re-resolves at startup.
sudo systemctl restart locksmith
```

In-flight requests drain within `shutdown.drain_window_seconds` (default 30s). The agent listener stops accepting new connections immediately on SIGTERM.

---

## 5. Degraded mode (per INF-4 / Q-17)

A single tool's credential failing to resolve **must not take the daemon down**. Instead:

- The tool is omitted from `/tools` (no agent will route to it).
- `readyz` reports `not_ready` with `tools: [<degraded_names>]` until every declared-auth tool resolves.
- Other tools and the admin surface keep working.

Verified by `tests/secret_proxy_integration_test.rs::missing_sealed_file_degrades_tool_quietly`.

To diagnose a degraded tool:

```bash
journalctl -u locksmith | grep "tool credential failed to resolve"
# Logs the tool name, the error, and the SecretRef variant.
```

---

## 6. Verifying M5 end-to-end

From the repo root:

```bash
# Unit/integration tests for the secret module.
cargo test --test secret_ref_parse_test
cargo test --test secret_backend_env_test
cargo test --test secret_backend_file_sealed_test
cargo test --test secret_backend_stubs_test

# Daemon-driven integration: sealed creds reach the proxy hot path.
cargo test --test secret_proxy_integration_test

# Full suite.
cargo test --tests
```

All binaries must report `test result: ok`.

For a manual smoke test against a real sealed deployment, follow `dist/examples/sealed-secrets/README.md` §6 ("Verify the threat boundary").

---

## 7. Common errors

| Error | Diagnosis | Fix |
|-------|-----------|-----|
| `tool credential failed to resolve` | Tool's SecretRef path/var/blob is wrong | Check `journalctl -u locksmith` for the named tool |
| `file mode 0644 permits group or world read` | Sealed file is not 0600/0400 | `chmod 0600` (systemd-creds normally drops files at 0400 — investigate why this one isn't) |
| `Missing(API_KEY)` from `FromEnv` | env var isn't set in the daemon's environment | systemd: use `Environment=` or `EnvironmentFile=`; container: pass `--env-file` |
| `not implemented: from_vault` | Tool uses `from_vault:` but Vault backend is a v2 stub | Use `from_file_sealed:` until live Vault impl lands post-v2 |
| `not implemented: from_aws_secrets_manager` | Same | Use `from_file_sealed:` (or `from_env:` with a file-templated env) |

---

## 8. What M5 does not include

- **Hot reload of credentials.** Restart-only for v0.6.0; future enhancement.
- **Live Vault integration.** Stub only (T5.3). Use systemd-creds + a sidecar that templates the value, or a pre-deploy step that pulls from Vault and seals.
- **Live AWS Secrets Manager integration.** Stub only.
- **HSM-backed signing.** Out of scope for v2 entirely (post-v2 work).
- **Per-tool credential rotation cadence.** Operator-driven; document your rotation schedule out-of-band.

---

*M5 closes the at-rest hole that operator-readable config + plaintext env vars left open. The next milestone (M6) closes the on-the-wire hole via mTLS for agent + operator auth.*
