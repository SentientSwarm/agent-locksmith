# M4 — Remote Management Runbook

**Audience:** operators enabling remote admin access to a Locksmith deployment, and engineers verifying the M4 acceptance contract before merging to `develop`.

**Covers:** the admin HTTPS listener (C-3, SPEC §4.2.5), TLS cert/key provisioning, CLI usage with `--admin-url` / `LOCKSMITH_ADMIN_URL`, and the listener-shape carve-out for cert rotation.

---

## 1. M4 acceptance checklist

| Criterion | Source | Verified by |
|-----------|--------|-------------|
| `listen.admin_https` config block parses | R-F10, T4.1/T4.3 | `tests/config_strict_test.rs` (parse) + `tests/admin_https_test.rs` |
| Off-by-default: no admin HTTPS port bound when block absent or `enabled: false` | T4.3 | `tests/admin_https_off_by_default_test.rs` (2 tests) |
| Cert/key fail-fast on missing file | T4.2 | `tests/admin_https_pem_load_test.rs::load_tls_config_missing_*` |
| Cert/key fail-fast on malformed PEM | T4.2 | `tests/admin_https_pem_load_test.rs::load_tls_config_malformed_pem_fails_fast` |
| Same router as UDS — every admin op works over HTTPS | UC-11, T4.3 | `tests/admin_https_test.rs::admin_https_create_and_list_agent_round_trip` |
| Bootstrap-token register works over HTTPS without operator bearer (D-10) | T4.5 | `tests/admin_https_test.rs::admin_https_bootstrap_register_works_without_bearer` |
| CLI `--admin-url` flag routes over HTTPS | T4.4 | `tests/cli_admin_https_test.rs::cli_admin_url_flag_routes_over_https` |
| CLI `LOCKSMITH_ADMIN_URL` env var routes over HTTPS | T4.4 | `tests/cli_admin_https_test.rs::cli_admin_url_env_var_routes_over_https` |
| Cross-transport contract: identical JSON between UDS and HTTPS for the same operation | T4.3 | `tests/cli_admin_https_test.rs` (`assert_eq!(https_body, uds_body)`) |
| Cert/key paths are listener-shape (rotation requires restart) | R-N5, T4.6 | this runbook + rustdoc on `AdminHttpsConfig` |
| `cargo clippy --all-targets -- -D warnings` clean | engineering std | local CI mirror |
| `cargo fmt --check` clean | engineering std | local CI mirror |

---

## 2. Generating cert + key

### Option A — smallstep (recommended, prod)

```bash
step certificate create locksmith.example.com \
    server.crt server.key \
    --profile leaf \
    --not-after 8760h \
    --san locksmith.example.com \
    --san 100.64.1.5            # Tailscale IP, optional
```

Then sign with your CA:

```bash
step ca sign server.crt --provisioner my-provisioner
```

### Option B — self-signed (homelab / dev)

```bash
openssl req -x509 -newkey rsa:4096 -nodes -days 365 \
    -keyout server.key -out server.crt \
    -subj "/CN=locksmith.local" \
    -addext "subjectAltName=DNS:locksmith.local,IP:127.0.0.1"
```

The CA bundle the CLI trusts is whatever cert chain validates `server.crt`. For self-signed, `server.crt` itself is the bundle.

### Permissions

```bash
chown locksmith:locksmith server.crt server.key
chmod 0640 server.crt server.key   # readable by daemon, group, no world
```

The cert is loaded once at boot — no need for the daemon process to have ongoing access if it's chrooted.

---

## 3. Daemon config

Add an `admin_https` block under `listen`:

```yaml
listen:
  host: "127.0.0.1"
  port: 9200
  admin_socket:
    path: "/var/run/locksmith/admin.sock"
  admin_https:
    enabled: true
    host: "0.0.0.0"                          # or 100.64.1.5 for Tailscale-only
    port: 9201
    cert_path: "/etc/locksmith/tls/server.crt"
    key_path: "/etc/locksmith/tls/server.key"
```

**Defaults:** `enabled: false`, `host: 127.0.0.1`, `port: 9201`.

Restart the daemon after changing any field under `admin_https` (see §6 below).

---

## 4. CLI usage

### Operator side (remote)

```bash
export LOCKSMITH_ADMIN_URL="https://locksmith.example.com:9201"
export LOCKSMITH_CA_BUNDLE="/etc/ssl/certs/locksmith-ca.crt"   # private CA
export LOCKSMITH_OP_TOKEN="lkop_..."

locksmith agent list
locksmith agent register --name agent-frontend
locksmith audit query --event-class operator --limit 50
```

Equivalent flag form:

```bash
locksmith \
    --admin-url https://locksmith.example.com:9201 \
    --ca-bundle /etc/ssl/certs/locksmith-ca.crt \
    agent list
```

Flag wins over env. Both omitted → CLI falls back to local UDS at `--socket` (or `LOCKSMITH_SOCKET`, default `/var/run/locksmith/admin.sock`).

### CA bundle

The CLI uses the system root store by default. Provide `--ca-bundle` (or `LOCKSMITH_CA_BUNDLE`) when the daemon presents a self-signed or private-CA certificate. This is the common case for smallstep / openclaw-hardened / Tailscale deployments.

### Same commands work

Every CLI subcommand routes through the same handler functions whether transport is UDS or HTTPS — the M4 contract. If a command works over UDS it works over HTTPS, and the JSON output is byte-identical.

---

## 5. Bootstrap registration over HTTPS

Per D-10, bootstrap-token register stands on its own — it's the only admin endpoint reachable without operator auth. This works over HTTPS exactly as over UDS:

```bash
# Operator mints a single-use bootstrap token (locally or remotely):
locksmith bootstrap mint --single-use

# Output: lkbt_...

# Agent host (no LOCKSMITH_OP_TOKEN set):
curl -X POST https://locksmith.example.com:9201/admin/agent/register \
    --cacert /etc/ssl/certs/locksmith-ca.crt \
    -H 'content-type: application/json' \
    -d '{"bootstrap_token":"lkbt_...","name":"agent-X"}'
```

The agent host needs only:
- TCP connectivity to the admin HTTPS port
- The bootstrap token
- The CA bundle (if the cert is private-CA)

No operator credentials. No UDS access.

---

## 6. Listener-shape carve-out (T4.6)

The `admin_https` block is **listener-shape config** under R-N5: a change to any of these fields requires a restart, even when full hot-reload of other config arrives in a future milestone.

Specifically, the following require restart:

- `enabled` (toggling the listener on/off)
- `host`, `port` (rebinding requires fresh TCP socket)
- `cert_path`, `key_path` (currently — until a hot-reload path lands; see §6.1 below)

### 6.1 Why cert rotation requires restart today

`axum-server`'s `RustlsConfig` *does* support hot reload via `RustlsConfig::reload_from_pem_file`, and in a future revision Locksmith may wire periodic refresh against the configured paths. For v0.5.0, cert rotation is restart-only:

```bash
# Drop the new cert+key in place
sudo cp -p new-server.crt /etc/locksmith/tls/server.crt
sudo cp -p new-server.key /etc/locksmith/tls/server.key

# Reload via systemd (graceful)
sudo systemctl reload locksmith   # if service file translates reload→restart, see M5 runbook
sudo systemctl restart locksmith  # otherwise
```

In-flight requests drain within `shutdown.drain_window_seconds` (default 30s). New connections are accepted by the new daemon process within ~2 seconds.

### 6.2 Off-by-default

If `admin_https` is absent, **the daemon does not bind any HTTPS listener.** This is verified by `tests/admin_https_off_by_default_test.rs` and is the contract for safe rollouts: an operator can leave the `admin_https` block entirely out of their config (or set `enabled: false`) and be guaranteed the surface is not exposed.

---

## 7. Verifying M4 end-to-end

From the repo root, with the daemon running and an operator token in env:

```bash
# 1. Off-by-default check
cargo test --test admin_https_off_by_default_test

# 2. PEM-load fail-fast
cargo test --test admin_https_pem_load_test

# 3. Listener round-trip
cargo test --test admin_https_test

# 4. CLI cross-transport contract
cargo test --test cli_admin_https_test
```

All four binaries must report `test result: ok` with 100% pass.

For a manual smoke test against a real deployment:

```bash
locksmith --admin-url https://locksmith.example.com:9201 \
    --ca-bundle /path/to/ca.crt \
    agent list

# Should match locally:
locksmith --socket /var/run/locksmith/admin.sock agent list
```

The two outputs (with `--format json`) must be `diff`-clean.

---

## 8. Common errors

| Error | Cause | Fix |
|-------|-------|-----|
| `TLS PEM load failed` at startup | `cert_path` / `key_path` missing or unreadable by the daemon user | `chown locksmith:locksmith` and `chmod 0640` |
| `error decoding response body: invalid certificate` (CLI) | Daemon's cert chain is not trusted by the CLI's CA store | Pass `--ca-bundle` or `LOCKSMITH_CA_BUNDLE` |
| `connect /var/run/locksmith/admin.sock: No such file or directory` (CLI) | `--admin-url` / `LOCKSMITH_ADMIN_URL` not set, fell back to UDS but daemon is remote | Set `LOCKSMITH_ADMIN_URL` |
| `https transport: error sending request: connection refused` | Listener not bound (check `enabled: true`), wrong port, or firewall | `ss -tlnp \| grep 9201` on the daemon host |
| 401 from HTTPS endpoint | Missing or wrong `LOCKSMITH_OP_TOKEN` | Re-export the operator token |

---

## 9. What M4 does not include

- **mTLS for agents/operators.** That's M6 (T6.7 specifically for operator client certs). M4 is bearer-only.
- **CRL / OCSP / revocation lists.** Also M6.
- **Cert hot reload.** Restart-only for v0.5.0; future enhancement.
- **Listener-shape config validation by hot reload.** v0.5.0 has no hot-reload path; that's T2.20 territory.
- **Multiple admin HTTPS listeners.** A single bind only. Multi-bind would be a new task.

---

*M4 closes UC-11 and the remote-management hole that blocked openclaw-hardened operators from administering Locksmith without host-shell access.*
