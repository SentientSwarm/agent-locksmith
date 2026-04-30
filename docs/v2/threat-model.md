# Threat Model — Agent Locksmith v2

**Status:** v0.6.0 (M5 closure)
**Audience:** operators planning a Locksmith deployment, security reviewers, and engineers proposing changes that move trust boundaries.

This document names what Locksmith protects against, what it does not, and which controls in M1–M5 cover which threats. It is not a substitute for SPEC §15 (D-1..D-18) — read that for the architectural decisions; this document is the threat-side companion that explains *why* those decisions exist.

The mitigations matrix in §4 is the load-bearing artifact: every claim "M5 hardens against X" should appear there with a pointer to the test or runbook that pins it.

---

## 1. Trust model

### 1.1 Trust boundaries

| Boundary | Above (trusted) | Below (untrusted) |
|----------|-----------------|-------------------|
| **Process boundary** | Locksmith daemon process | Anything not running as the `locksmith` uid |
| **Filesystem boundary** | `chmod 0640`/`0600` files owned by `locksmith` | Group-readable, world-readable, or other-uid-owned files |
| **Network — agent listener** | Local agents that present a valid bearer (M2) or, in M6, mTLS client cert | Anyone else on the network |
| **Network — admin UDS** | Operators with filesystem access to the socket AND a valid operator bearer | Anyone without socket access |
| **Network — admin HTTPS (M4)** | Operators with TLS access AND a valid operator bearer | Anyone without bearer |

### 1.2 Threat actors

- **Curious operator (low):** has shell access on the host. Does not actively attack but might inspect files. Threat: secrets in operator-readable config.
- **Compromised non-root user (medium):** an attacker who got code execution as a non-locksmith user (e.g. via a co-located service exploit). Threat: reading shared filesystem, network access.
- **Compromised locksmith uid (high):** code execution *as* the locksmith user. Threat: anything the daemon could do, plus reading process memory.
- **Compromised root (critical):** total host compromise. **Out of scope.** Locksmith is not a defense-in-depth product against root.
- **External network attacker (medium):** off-host attacker reaching the listener over network. Threat: brute-force auth, exploit vulns in TLS / proxy stack.
- **Compromised upstream (medium):** the inference provider or tool target itself is malicious. Threat: data exfiltration via response, request smuggling. Mitigated by M7 response controls.

---

## 2. In-scope threats (what M1–M5 hardens against)

### T1 — Credential disclosure to a curious operator

**Surface:** an operator with read access to `/etc/locksmith/config.yaml` reads secret values.

**Mitigation (M5/T5.1):** `tool.auth.value: from_file_sealed: { path: ... }`. The config file holds only the *path* to the encrypted blob. The blob is encrypted by `systemd-creds encrypt`; only systemd (running as PID 1) can decrypt it, and only at service start. The decrypted plaintext lands in `/run/credentials/locksmith/$NAME` (tmpfs, mode 0400, owned by locksmith). An operator without root cannot read the plaintext.

**Residual risk:** an operator with sudo can still read `/run/credentials/locksmith/$NAME` (it's the same file the daemon reads). systemd-creds does not protect against root.

### T2 — Naïve disk image disclosure

**Surface:** stolen drive, leaked backup, accidental snapshot.

**Mitigation (M5/T5.1):** the encrypted blob is bound to the host's TPM (or system identity) when sealed with `systemd-creds encrypt`. A blob copied to another machine cannot be decrypted there. The Locksmith DB (`/var/lib/locksmith/locksmith.db`) holds **only argon2 hashes** of agent + operator + bootstrap-token secrets, never plaintext. JSONL audit (M3) holds no secret material per the audit model in SPEC §4.6.2.

**Residual risk:** if the attacker also has the host's TPM or the systemd-creds master key (stored encrypted at `/var/lib/systemd/credential.secret`), they can decrypt. The TPM-bound case requires physical access to the original host.

### T3 — Restart-time / shutdown-time memory scrape

**Surface:** dump of `/proc/<pid>/mem` after a crash, or a dump captured during a controlled shutdown.

**Mitigation (M5/T5.1):** resolved credentials are held in `secrecy::SecretString` which zeroizes on `Drop`. The daemon's clean shutdown path drops the resolver's cache before exit. systemd unit (`T5.2`) enables `MemoryDenyWriteExecute=yes` to block one common class of in-process scraping helper.

**Residual risk:** between credential resolution at startup and the explicit drop on shutdown, the secrets *do* live in process memory. The next class (T7) addresses this.

### T4 — Brute-force on agent / operator tokens

**Surface:** an attacker on the network probing `/admin/agent/register` or the agent listener with random bearer tokens.

**Mitigation (M2):** all tokens are argon2-id hashed at rest with the standard params (Q-13: m=4 MiB, t=3, p=1) yielding ~5ms verify cost. Decoy-on-miss verification means timing leaks don't reveal whether a public_id exists. M2.x carry-over T2.11 (RateLimiter) bounds the attack rate; until it lands, operators rely on nginx/Caddy in front.

**Residual risk:** without RateLimiter, a determined attacker can attempt ~200/sec/core. That's still ~ten million years for a 24-byte secret.

### T5 — Lateral movement via stolen agent token

**Surface:** an attacker who got hold of one agent's token uses it broadly.

**Mitigation (M2):** per-agent allowlist + denylist constrain blast radius to that agent's contracted tools. M3 audit logs every proxy request with the agent_public_id, making detection feasible. M2.4 schema gate ensured the per-agent identity is structurally enforced at the data layer.

**Residual risk:** within an agent's allowlist, the token is fully empowered. Operators must scope agents narrowly.

### T6 — Configuration tampering

**Surface:** an attacker modifies `/etc/locksmith/config.yaml` to redirect tools, extend allowlists, or swap secret backends.

**Mitigation (M5/T5.2):** systemd unit ships `ProtectSystem=strict` so the daemon itself cannot write `/etc`. Tampering requires root + bypass of file system ACLs. M2 hot-reload validates new configs before swap; an unparseable config is rejected, leaving the running config intact.

**Residual risk:** root tampering plus restart can swap the config. Defense is filesystem ACL hygiene + audit alerting.

---

## 3. Out-of-scope threats (Locksmith does not defend)

### T7 — Compromised locksmith uid (running-process memory)

If an attacker gets code execution as the `locksmith` user, they can read `/proc/self/maps`, walk the heap, and recover any resolved credential currently held in `SecretString`. **No process-level memory hardening prevents this** without HSM-style per-request decryption (out of scope for v2).

### T8 — Kernel exploit / root compromise

A kernel exploit gives the attacker arbitrary host access. Locksmith's mitigations (`NoNewPrivileges`, `MemoryDenyWriteExecute`, etc.) raise the bar but are not a defense against a working kernel exploit. Likewise, a compromised root account can read everything.

### T9 — Side-channel attacks on the host CPU

Timing, power, EM-emission, microarchitectural side channels. Out of scope.

### T10 — Supply-chain compromise of dependencies

A backdoor planted in `axum`, `rustls`, or `sqlx` is not something Locksmith can detect. Operators should pin dependency versions (`Cargo.lock` is checked in) and verify upstream provenance through whatever process they use for other Rust services.

### T11 — Physical access to a running host

Attached debugger, cold-boot RAM extraction. Out of scope.

---

## 4. Mitigations matrix

| Threat | Severity | Surface | Mitigation | Where it lives | Test / runbook |
|--------|----------|---------|------------|----------------|----------------|
| T1 — operator reads secrets in config | Medium | Operator-readable config | `from_file_sealed:` + systemd-creds | M5 / T5.1 | `tests/secret_proxy_integration_test.rs::from_file_sealed_credential_reaches_proxy_hot_path` + `docs/v2/runbooks/m5-sealed-secrets.md` |
| T2 — disk image disclosure | High | Backups, stolen drive | TPM-bound systemd-creds + argon2 hashes only in DB | M2 schema + M5/T5.1 | `migrations/0001_init.sql` (column types) |
| T3 — memory scrape at shutdown | Medium | `/proc/$pid/mem` dumps | `secrecy::SecretString` zeroize + `MemoryDenyWriteExecute` | M5/T5.1 + T5.2 | `dist/systemd/locksmith.service.template` |
| T4 — token brute-force | Low | Network listener | argon2id (Q-13 params) + decoy-on-miss + (future T2.11 rate limit) | M2 | `tests/auth_v2_*` |
| T5 — lateral movement via stolen agent token | Medium | Network listener | Per-agent allowlist + audit | M2 + M3 | `tests/audit_proxy_test.rs` |
| T6 — config tampering | Medium | `/etc/locksmith/` | `ProtectSystem=strict` + hot-reload validate-before-swap | M5/T5.2 + M2 | systemd template + `tests/config_*` |
| T7 — running-process memory | Critical | locksmith uid | **Out of scope** | — | — |
| T8 — kernel exploit / root | Critical | Host root | **Out of scope** | — | — |
| T9 — side channels | Critical | Host CPU | **Out of scope** | — | — |
| T10 — supply chain | Variable | Crate ecosystem | Pin `Cargo.lock`; operator-provenance | — | — |
| T11 — physical access | Critical | Host hardware | **Out of scope** | — | — |

---

## 5. Residual risk summary

If you accept Locksmith's deployment model — non-root daemon, systemd-creds-sealed credentials, hardened unit file, M2 per-agent identity, M3 audit, M4 admin HTTPS over a private CA, M6 mTLS (when it lands) — then the residual risk is:

1. **An attacker who can run code as `locksmith` reads everything.** Compensating control: keep the host attack surface small (single-purpose VM, no co-located services).
2. **Root reads everything.** Compensating control: limit who has sudo on the host.
3. **A 0-day in `axum` / `rustls` / `tokio` could give RCE.** Compensating control: dependency monitoring + fast patch cadence.

Locksmith is a useful link in a chain. It is not the chain.

---

## 6. Future work that moves the boundary

- **M6 mTLS** (next milestone) closes the bearer-token-on-the-wire surface for agent + operator authentication. A stolen bearer token without the matching cert is useless.
- **M7 response controls** add per-tool size/content-type/redaction enforcement, blunting T-class threats from compromised upstreams.
- **Post-v2 KMS-backed credentials.** A live VaultBackend (T5.3 stub today) lifts the residual risk in T1: secrets never live on disk in a host-bound form. Daemon resolves through Vault on each startup; rotation happens out-of-band.
- **Post-v2 HSM-backed signing.** For deployments that genuinely need T7 protection, the credential never lives in process memory — the daemon asks the HSM to sign each upstream request. Adds latency; only worth it for very high-value secrets.

---

*This document evolves with each milestone. M6 will add mTLS-specific threats (CRL freshness, blocklist hot-reload). M7 will add response-side T-class entries.*
