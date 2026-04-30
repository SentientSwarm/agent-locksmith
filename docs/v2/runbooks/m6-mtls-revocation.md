# M6 — mTLS Revocation Runbook

**Audience:** operators responding to a credential compromise or off-cycle revocation event.

**Goal:** revoke a cert effective within seconds (local emergency blocklist) or hours (CRL refresh), with audit trail.

---

## Decision: emergency blocklist vs CRL

Use the **local emergency blocklist** when:
- You need revocation to take effect within seconds, not the next CRL refresh window.
- The CA's CRL distribution is slow or unavailable.
- You're not yet running a CRL.

Use the **CA's CRL** when:
- The compromise is broader than one agent and you want fleet-wide CRL distribution.
- You don't trust your blocklist file's integrity (use the CA's authority instead).
- You're rotating in the normal cadence and not under incident pressure.

Both compose. The blocklist is a local override; CRL is the source of truth for the fleet.

---

## 1. Emergency: revoke immediately

```bash
# Find the serial. Either from your audit logs:
locksmith audit query --agent <public_id> --format json \
    | jq -r '.[] | .details.serial_hex' | sort -u | head -3

# Or from the cert itself:
openssl x509 -in agent-7.crt -noout -serial

# Add to the emergency blocklist:
sudo locksmith mtls revoke <SERIAL_HEX> \
    --blocklist-path /etc/locksmith/blocklist \
    --reason "incident 2026-04-30: key exfiltration suspected"
```

The daemon's blocklist watcher picks up the change within
`mtls.blocklist_reload_interval_seconds` (default 30s). The next request from this serial is rejected with `mtls_auth_failure reason=revoked_by_blocklist`.

```bash
# Verify:
sudo locksmith mtls list-blocklist --blocklist-path /etc/locksmith/blocklist
# Then watch the audit for the revoked-by-blocklist row:
locksmith audit query --event-class security --limit 5 --format json
```

---

## 2. Standard: CRL revocation

```bash
# At your CA (smallstep example):
step ca revoke --provisioner agent-onboarding <SERIAL>

# Wait for the next CRL refresh (default 1 hour) OR force a refresh
# by restarting the daemon:
sudo systemctl restart locksmith
```

Full propagation timing: `mtls.crl_refresh_interval_seconds` (default 3600). Tune down if your incident response SLA requires faster propagation.

---

## 3. Verify the revoke landed

The audit row format on a rejected request:

```json
{
  "event_class": "security",
  "event": "mtls_auth_failure",
  "decision": "denied",
  "auth_method": "mtls",
  "details": {
    "reason": "revoked_by_blocklist",   // or "revoked_by_crl"
    "serial_hex": "...",
    "message": "..."
  }
}
```

Search:

```bash
locksmith audit query --event-class security \
    --since-ms <minutes_ago> --format json \
    | jq '.[] | select(.event == "mtls_auth_failure")'
```

---

## 4. Long-running incident

For an incident spanning multiple hours:

1. Add to the local blocklist immediately (covers the next 30s).
2. Revoke at the CA within the first hour (covers the next CRL window).
3. After 24 hours, you can trim the local blocklist if the CRL has propagated. Keep entries for actively-compromised serials indefinitely as a safety belt.

---

## 5. Rotating an agent's cert (no compromise)

Standard rotation does NOT require revocation — just issue a new cert and let the old one expire:

```bash
ssh agent-host -- step ca certificate "agent-7" \
    /etc/locksmith-agent/cert.pem.new \
    /etc/locksmith-agent/key.pem.new \
    --provisioner agent-onboarding

ssh agent-host -- mv /etc/locksmith-agent/cert.pem.new /etc/locksmith-agent/cert.pem
ssh agent-host -- mv /etc/locksmith-agent/key.pem.new /etc/locksmith-agent/key.pem
ssh agent-host -- systemctl reload locksmith-agent   # or whatever process holds the cert
```

The cert_identity stays the same; the new cert just chains to the same value.

---

## 6. Common mistakes

| Mistake | Outcome |
|---------|---------|
| Revoke at CA but forget to push CRL | Blocklist stays empty; fleet keeps trusting the cert until next CRL refresh |
| Add wrong serial to blocklist | False positives; audit will show innocent agents rejected |
| Skip `--reason` flag | Future operators can't reconstruct why a serial is on the list. Always include it. |
| Edit blocklist file with wrong perms | Daemon's watcher might miss the change. Use the CLI to keep ownership/perms consistent. |

---

## 7. Tabletop drill

Run this once a quarter:

1. Pick a non-critical agent.
2. Revoke its cert with the emergency blocklist.
3. Verify within 30 seconds (audit + denied request).
4. Remove from blocklist; verify access restores within 30 seconds.

The drill exercises the full path under controlled conditions and surfaces config drift before it bites in a real incident.
