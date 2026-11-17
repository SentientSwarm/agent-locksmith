# Trust boundary

User-level explanation of who holds what credential and why.

## The core idea

**Agents never see provider API keys.** A locksmith deployment exists to make this guarantee concrete, mechanical, and auditable. Anything else — ACL, audit, scanners — is downstream of that single invariant.

When an agent calls `https://api.anthropic.com/v1/messages` through Locksmith, the request looks like:

```
agent → POST /api/anthropic/v1/messages          Authorization: Bearer lk_<public_id>.<secret>
locksmith verifies the bearer, looks up agent, checks ACL, strips the header
locksmith → POST https://api.anthropic.com/v1/messages   x-api-key: <real anthropic key>
```

The agent code never had access to the real Anthropic key. The only credential it ever held was its own bearer — narrowly scoped to its allowlist.

## The three roles

| Role | Holds | Lives where |
|------|-------|-------------|
| **Operator** | Provider API keys, operator credential to admin substrate, agent registration permission | Sealed at rest on the proxy host. Cleartext only ephemerally during deploy/rotation. |
| **Agent deployer** | Per-agent bearer token (one only, theirs) | Distributed by the operator out-of-band. Stored mode 0600 on the agent host; sealed at rest in v0.2. |
| **Agent (running code)** | Per-agent bearer token (theirs only) | Read into memory at startup; never persisted by the agent itself. |

Operator and agent deployer are often the same person at v0.1.0 — single human running `bootstrap-operator.py` then `register-agents.sh`. v0.2 separates them: operator has admin credential and provider keys; agent deployer is privileged enough to register an agent and receive a one-time bearer, but doesn't see provider keys.

## What this buys you

- **Provider key compromise blast radius**: only the proxy host. An exfiltrating agent can't ship the key out — it never had it.
- **Per-agent revocation**: rotating one agent's access is a single `locksmith agent revoke <name>`. No need to rotate the underlying provider keys.
- **Audit attribution**: every upstream request carries the originating `agent_public_id` in the locksmith audit log, derived from the authenticated bearer.
- **No header leakage**: the real provider key never traverses the agent's code path, so it can't end up in an agent's request log, an LLM prompt, or a stack trace.

## What it doesn't buy you

- **Side-channel exfiltration**: an agent that can call `anthropic` can send any prompt content it wants. Egress allowlisting and Locksmith's inline content inspection (see [egress and inspection](egress-and-inspection.md)) are the perimeter for that — separate concerns from trust-boundary.
- **Compromised proxy host**: if the host is compromised, the sealed creds + admin credential are at risk. Defense in depth via at-rest sealing (v0.2) and audit (always on) reduces but doesn't eliminate this.
- **Agent code integrity**: locksmith doesn't verify the agent binary. A malicious agent with a valid bearer can do anything its ACL permits. Allowlist tightly.

## The bearer token format

```
lk_<public_id>.<secret>
```

- `lk_` namespace marker — every locksmith bearer starts with this.
- `<public_id>` opaque identifier; safe to log, appears in audit rows.
- `<secret>` random 256-bit value, hashed (argon2) at rest. Cleartext leaves the daemon exactly once — at registration time. Operator distributes it out-of-band.

A token that doesn't match this shape is rejected with the same 401 + audit row as a token whose components are individually wrong (Q-8 existence-leak avoidance — see [error-envelope](error-envelope.md)).

## Operator practical guidance

- **Sealing**: keep provider keys as sealed `stored_*` values under `LOCKSMITH_CREDENTIAL_SEALING_KEY` or as `op://` references. See [keep credentials in Locksmith](../../guide/03-credential-custody.md). Cleartext should exist only while you set the value. Systemd-encrypted credential files (`LoadCredentialEncrypted`) apply only to legacy `config.tools` entries and cannot be selected for an agent; see [per-agent credentials](per-agent-credentials.md) to move them into custody.
- **Distributing bearers**: operator runs `locksmith agent register --name <agent> --allowlist <tools> --format json`, captures the cleartext token from stdout once, then delivers it to the agent host via a side channel (encrypted message, paste over SSH, etc.). The locksmith DB stores only the hash.
- **Rotation**: revoke + re-register; the agent's old bearer hard-fails with 401 immediately.

## See also

- [agent-identity-and-acl.md](agent-identity-and-acl.md) — what's inside a bearer (AgentIdentity), how ACL is enforced.
- [error-envelope.md](error-envelope.md) — the wire shape when a bearer is missing/invalid/expired.
