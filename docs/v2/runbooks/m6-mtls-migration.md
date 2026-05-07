# M6 — mTLS Migration Runbook

**Audience:** operators rolling out mTLS to an existing bearer-token fleet.

**Goal:** zero-downtime migration from `auth_mode: bearer` to `auth_mode: mtls`, with per-agent visibility along the way.

---

## Migration sequence

```
bearer  →  both  →  mtls
```

Each step is a daemon restart. Move the whole fleet to `both` first; verify; then flip to `mtls`. Skipping `both` means agents that haven't yet gotten certs lose access on the cutover.

---

## 1. Stage A — flip to `both`

Prep:
1. Provision the agent CA bundle (see `m6-mtls-onboarding.md` §2).
2. Decide how you'll bind cert_identity to existing agents (SQL UPDATE in v0.7.0; CLI in v0.7.x).
3. Plan the agent-side cert rollout — usually Ansible / a config management run that drops cert+key on each host.

Daemon config:
```yaml
listen:
  auth_mode: both
  mtls:
    ca_bundle_path: "/etc/locksmith/agents-ca.crt"
```

Restart. Now both bearer AND mTLS work; either authenticates an agent. Audit the migration progress:

```bash
locksmith audit query --since-ms <yesterday> --format json \
    | jq -r '.[] | [.ts_ms, .agent_public_id, .auth_method] | @tsv'
```

Watch for `auth_method` flipping from `bearer` to `mtls` per agent. When the entire fleet has at least one mTLS-authenticated request, you're ready for stage B.

---

## 2. Stage B — flip to `mtls`

Daemon config:
```yaml
listen:
  auth_mode: mtls
```

Restart. Bearer requests now fail with 401 `invalid_credential`. Agents WITHOUT certs cannot authenticate.

The bootstrap-only listener (T6.8) stays available so new agents can register without certs and pick up their cert as part of onboarding.

---

## 3. Rollback

Either stage can roll back by editing the config and restarting:

- `mtls` → `both`: agents that lost their certs can fall back to bearer until you re-issue.
- `both` → `bearer`: rare, but supported. Operators who roll back to bearer typically also disable the bootstrap-only listener (it's only useful in mTLS mode).

---

## 4. Per-agent visibility during migration

The audit table is the migration progress dashboard.

```sql
-- Agents NOT yet observed using mTLS:
SELECT a.public_id, a.name
FROM agents a
WHERE a.revoked_at IS NULL
AND NOT EXISTS (
    SELECT 1 FROM audit
    WHERE agent_public_id = a.public_id
    AND auth_method = 'mtls'
    AND ts_ms > strftime('%s', 'now', '-7 days') * 1000
);
```

Empty result = whole fleet has rotated. Safe to flip to `mtls`.

---

## 5. Failure modes during migration

| Symptom | Cause | Fix |
|---------|-------|-----|
| Agent fails authentication after stage B | cert_identity not set on agent record | Set it (SQL or future CLI), have agent retry |
| `untrusted_chain` audit row | Agent's cert was issued by a different CA than `ca_bundle_path` | Re-issue the cert from the right CA OR add the issuing CA to the bundle |
| `cert_expired` audit row | Agent cert past notAfter | Re-issue via your CA's renewal flow |
| All agents fail simultaneously | Wrong CA bundle path or unreadable | Check `journalctl -u locksmith` for the load error; restart |

---

*Continue to `m6-mtls-revocation.md` for incident response procedures.*
