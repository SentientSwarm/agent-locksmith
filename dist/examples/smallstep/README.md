# Worked example — mTLS with smallstep / step-ca (T6.11)

End-to-end recipe for an Agent Locksmith deployment where every agent
authenticates with a client cert issued by [smallstep](https://smallstep.com/)'s
step-ca. Operators get the same path for the admin HTTPS listener.

This example targets the M6 mTLS surface (T6.1–T6.10). Read
`docs/v2/runbooks/m6-mtls-onboarding.md` first for the threat model
and rotation procedure.

---

## Prerequisites

- step-ca running and reachable (`https://step-ca.example.com:443`)
- step CLI installed locally
- A bootstrap-only listener configured on the daemon (see §3 below)

## File layout

```
/etc/locksmith/agents-ca.crt              # CA bundle the daemon trusts
/etc/locksmith/blocklist                  # local emergency blocklist (T6.4)
/etc/locksmith/operators.yaml             # operators.yaml with cert_identity
/etc/locksmith/config.yaml                # daemon config
/etc/locksmith/tls/server.{crt,key}       # admin HTTPS server cert
/etc/locksmith/tls/bootstrap.{crt,key}    # bootstrap-only listener cert
```

---

## 1. Provision the agent CA bundle

```bash
step ca root /etc/locksmith/agents-ca.crt --ca-url https://step-ca.example.com
```

## 2. Provision an agent cert

For each agent host:

```bash
ssh agent-host -- step ca certificate \
    "agent-7" \
    /etc/locksmith-agent/cert.pem \
    /etc/locksmith-agent/key.pem \
    --provisioner agent-onboarding \
    --san "agent-7.local" \
    --not-after 168h
```

The CN (`agent-7`) becomes the cert_identity in Locksmith. Bind it
when registering the agent (next step).

## 3. Onboard the agent via the bootstrap-only listener

On the operator host:

```bash
TOKEN=$(locksmith bootstrap mint --single-use --format json | jq -r .token)
echo "Bootstrap token: $TOKEN"
```

On the agent host (no operator credentials needed — D-10):

```bash
curl -X POST https://locksmith.example.com:9202/admin/agent/register \
    --cacert /etc/locksmith/agents-ca.crt \
    -H 'content-type: application/json' \
    -d "$(jq -n --arg t "$TOKEN" '{bootstrap_token: $t, name: "agent-7"}')"
# → { "public_id": "lk_...", "token": "lk_<id>.<secret>", ... }
```

Then bind the cert identity to the new agent (operator-side):

```bash
locksmith agent get agent-7 --format json | jq -r .public_id   # save it
# Use a future `locksmith agent set-cert-identity` command, or update
# the agent record via the admin API directly. For v0.7.0 the daemon
# exposes set_cert_identity at the AgentRepository layer; the CLI
# wrapper lands in v0.7.x.
```

## 4. Provision the operator cert (optional, T6.7)

```bash
step ca certificate \
    "alice@example.com" \
    /home/alice/.locksmith/op.crt \
    /home/alice/.locksmith/op.key \
    --provisioner operator-onboarding
```

Add the cert_identity to operators.yaml:

```yaml
operators:
  - name: alice
    public_id: "lkop_..."
    token_hash: "$argon2id$..."
    cert_identity: "alice@example.com"
```

## 5. Configure the daemon

See `config.yaml` in this directory.

## 6. Daily ops

### Revoke an agent immediately (emergency)

```bash
sudo locksmith mtls revoke <SERIAL_HEX> \
    --blocklist-path /etc/locksmith/blocklist \
    --reason "rotated key out of band"
```

The daemon's blocklist watcher picks the change up within
`mtls.blocklist_reload_interval_seconds` (default 30s). For longer
windows where you want CRL-based revocation, also revoke at step-ca:

```bash
step ca revoke --provisioner agent-onboarding <SERIAL>
```

### Inspect the blocklist

```bash
locksmith mtls list-blocklist --blocklist-path /etc/locksmith/blocklist
```

### Check CRL freshness

For v0.7.0 this command is a stub pointing at `journalctl`. A future
admin endpoint will surface the CrlStore snapshot directly.

```bash
journalctl -u locksmith | grep CRL
```

---

## 7. Verifying the threat boundary

- An attacker without a valid agent cert cannot authenticate to the
  agent listener (when `auth_mode: mtls`).
- A revoked cert (CRL or blocklist) is rejected within
  `mtls.crl_refresh_interval_seconds` (CRL) or
  `mtls.blocklist_reload_interval_seconds` (blocklist).
- An expired cert is rejected immediately.
- A cert issued by a different CA is rejected immediately.

See `docs/v2/threat-model.md` §2 T4–T5 for the full posture.

---

## 8. Common errors

| Symptom | Diagnosis |
|---------|-----------|
| `mtls_auth_failure reason=untrusted_chain` | Agent cert not signed by `mtls.ca_bundle_path` |
| `mtls_auth_failure reason=cert_expired` | Cert past `notAfter`. Re-issue. |
| `mtls_unknown_identity` | Cert chain valid but no agent has that cert_identity. Either misprovisioned cert or revoked agent. |
| `mtls_auth_failure reason=revoked_by_blocklist` | Operator added this serial to the local blocklist. Working as intended. |
| `mtls_auth_failure reason=revoked_by_crl` | step-ca issued a CRL update revoking this serial. Working as intended. |

See `docs/v2/runbooks/m6-mtls-revocation.md` for the incident-response
procedure.
