# Runbook: M9 — per-agent bearer + tool ACL on the proxy hot path

**Audience:** operators upgrading agent-locksmith to v2.0.0.
**Status:** breaking — read in full before upgrading.
**Companion docs:** SPEC §6.2 #M9 (design), HANDOFF §1 (branch state).

## What changed

`v1.x → v2.0.0` flips the agent listener's authentication contract **when the admin substrate is enabled** (`listen.admin_socket` + `database.path`):

| Behavior | v1.x | v2.0.0 |
|---|---|---|
| `auth_mode: bearer` with admin substrate enabled, no `inbound_auth.token` | permissive (every request authenticated as anonymous M0 bearer) | **per-agent bearer required** — every request must carry `Authorization: Bearer lk_<public_id>.<secret>` |
| `auth_mode: bearer` with admin substrate enabled and `inbound_auth.token` set | shared bearer enforced (one token for all agents) | **shared bearer silently ignored**; per-agent bearer takes precedence; one-shot deprecation warning at startup |
| `tool_allowlist` / `tool_denylist` recorded on each agent | inert — never consulted on `/api/<tool>/...` | **enforced on every request** — ACL miss returns 403 with audit row class `security` event `authz_denied` |
| `auth_mode: bearer` **without** admin substrate (no `admin_socket` / no `database.path`) | M0 shared-bearer via `inbound_auth.token` | **unchanged** — M0/M1 deployments are untouched by v2.0.0 |
| `auth_mode: mtls` / `both` | per-agent identity from cert, ACL inert | **per-agent identity from cert, ACL enforced** (the same gate that bearer hits) |

`auth_mode: bearer` keeps its name because the wire protocol on the listener is unchanged — only the auth substrate behind it changes.

## Migration recipe

### 1. Pre-flight check

```bash
# Are you affected? You are if the daemon's config has BOTH:
yq '.listen.admin_socket.path' config.yaml      # not null
yq '.database.path' config.yaml                 # not null
```

If either is null, you are running an M0/M1-shape deployment and the v2.0.0 upgrade is silent — no action required.

### 2. Bootstrap an operator credential

The operator credential lets you issue per-agent tokens via the locksmith CLI. You only need this once per locksmith instance.

```bash
# In the agent-locksmith deployment (e.g. layer8-proxy-site repo)
./scripts/bootstrap-operator.py
# Stores hashed credential in operators.yaml; seals the wire token via
# secrets.bootstrap.sh (systemd-creds on Linux, openssl on macOS dev).
```

The CLI then expects `LOCKSMITH_OP_TOKEN=lkop_<public_id>.<secret>` in its environment for any admin operation.

### 3. Register your agents

```bash
# Each agent gets its own bearer token, scoped to a specific tool list.
LOCKSMITH_OP_TOKEN=$(./scripts/decrypt-creds.sh operator_token) \
  locksmith agent register \
    --name "hermes-mini-m1" \
    --allowlist "lmstudio,lf-scan,tavily,github"

# Output includes the wire token: lk_<public_id>.<secret>
# Distribute it to the agent host (e.g. ~/.hermes/locksmith.token, mode 0600).
```

The site repos `layer8-proxy-site` and `hermes-site` automate this via `register-agents.sh` driven by an `agents.yaml` manifest.

> ⚠️ **Empty allowlist denies all tools.** `--allowlist ""` (or `--allowlist -` on `agent modify`) is treated as "no tools permitted" — every `/api/<tool>/...` request returns 403 `tool_not_allowed`. To grant unrestricted access, omit the `--allowlist` flag entirely.

### 4. Configure agents to send the bearer

Most agent frameworks read the LLM key from an env var. Wrap the locksmith proxy URL with the per-agent bearer:

```bash
# hermes-site/launch-hermes.sh — example
export LOCKSMITH_TOKEN="$(cat ~/.hermes/locksmith.token)"
# hermes.config.yaml then expands ${LOCKSMITH_TOKEN} into each tool's api_key.
```

### 5. Verify

```bash
# No-auth → 401
curl -i http://locksmith-host:9200/api/lf-scan/health
# Expected: HTTP/1.1 401 Unauthorized
#   {"error":{"message":"missing credential","type":"auth_error","code":"invalid_credential"}}

# Wrong bearer → 401
curl -i -H "Authorization: Bearer lk_invalid.xxx" \
  http://locksmith-host:9200/api/lf-scan/health
# Expected: HTTP/1.1 401 Unauthorized
#   {"error":{"message":"invalid credential","type":"auth_error","code":"invalid_credential"}}

# Disallowed tool (token's allowlist excludes it) → 403
curl -i -H "Authorization: Bearer $LOCKSMITH_TOKEN" \
  http://locksmith-host:9200/api/dangerous-tool/anything
# Expected: HTTP/1.1 403 Forbidden
#   {"error":{"message":"tool access denied","type":"authz_error","code":"tool_not_allowed"}}

# Allowed tool → upstream's response
curl -i -H "Authorization: Bearer $LOCKSMITH_TOKEN" \
  http://locksmith-host:9200/api/lf-scan/health
# Expected: HTTP/1.1 200 OK (whatever the upstream returns)
```

### 6. Drop legacy `inbound_auth` block

If your `config.yaml` carried `inbound_auth.token` from M0/M1, the v2.0.0 daemon will warn at startup:

```
WARN  locksmith::deprecation  field=inbound_auth.token since_version=2.0.0
  shared inbound_auth.token is ignored when the admin substrate is enabled —
  per-agent bearer authentication takes precedence. Remove the inbound_auth
  block to silence this warning. (M9 / v2.0.0)
```

Removing the block is a one-line cleanup; it's silently ignored, so requests will not change behavior either way.

## Audit grep recipes

All M9 events live in the existing `audit` SQLite table (and JSONL mirror if configured). Use the locksmith CLI or `sqlite3` directly.

```bash
# Every security audit row in the last hour — filter client-side by event.
SINCE_MS=$(( $(date +%s) * 1000 - 3600 * 1000 ))

# Authentication failures (BearerAuthenticator) by reason
locksmith --format json audit query \
  --event-class security \
  --since-ms "$SINCE_MS" \
| jq '.[] | select(.event == "auth_failure")
            | {ts:.ts_ms, reason: .details.reason, agent: .agent_public_id}'

# Reason values: missing_credential, malformed_token, wrong_namespace,
#                unknown_public_id, secret_mismatch, expired

# ACL denies (proxy_handler) by reason and tool
locksmith --format json audit query \
  --event-class security \
  --since-ms "$SINCE_MS" \
| jq '.[] | select(.event == "authz_denied")
            | {ts:.ts_ms, agent: .agent_public_id, tool: .tool, reason: .details.reason}'

# Reason values: not_in_allowlist, in_denylist
```

Notes:
- `audit query` is the subcommand (no `audit list`). Filter by `event` client-side via `jq` because the daemon's `/admin/operator/audit` endpoint groups by `event_class`, not the finer-grained `event` string.
- `--since-ms` takes Unix milliseconds, not relative durations.
- `authz_denied` rows do not carry `upstream_host` (the gate runs before tool resolution), so joins on `upstream_host` won't surface ACL denies.

## Troubleshooting

**Symptom:** all agent requests return 401 immediately after upgrade.
**Cause:** admin substrate is enabled but no agents are registered.
**Fix:** run steps 2–4 above. Verify `locksmith agent list` shows your agent.

**Symptom:** specific agent's requests return 403 on a tool you expected to work.
**Cause:** the agent's `tool_allowlist` doesn't include that tool, or `tool_denylist` does.
**Fix:** `locksmith agent get <public_id_or_name>` to inspect; `locksmith agent modify <public_id> --allowlist "lmstudio,lf-scan,..."` to replace the allowlist, or `--allowlist -` to clear it (unrestricted). The denylist is independent: `--denylist a,b` to set, `--denylist -` to clear. `register-agents.sh` after editing `agents.yaml` is the operator-facing equivalent.

**Symptom:** startup warns about `inbound_auth.token` even though I removed it.
**Cause:** there's a stale `inbound_auth:` block (with `mode: bearer` but no `token:`). The deprecation gate checks `token` specifically; `mode` alone is ignored.
**Fix:** remove the entire `inbound_auth:` block from your config.

**Symptom:** mTLS deployment now returns 403 on a tool the agent's cert was authorized for.
**Cause:** mTLS already mapped the cert to an `AgentIdentity` in v1.x, but v2.0.0 now enforces that identity's `tool_allowlist` / `tool_denylist`. The agent's row in the admin DB has restrictive lists.
**Fix:** update the agent's ACL via `locksmith agent modify <public_id> --allowlist - --denylist -` to clear both lists (unrestricted), or set them explicitly with `--allowlist a,b,c` / `--denylist x,y`.

## Wire envelope reference

Per §4.7.9, all auth/authz failures use a uniform JSON envelope:

```json
{
  "error": {
    "message": "<human-readable>",
    "type": "auth_error" | "authz_error",
    "code": "invalid_credential" | "revoked" | "expired" | "rate_limited" | "backend_error" | "tool_not_allowed"
  }
}
```

`Retry-After` header is set when `code: rate_limited` (forward-compat — no current emitter).

The wire shape deliberately does NOT distinguish "no such agent" from "wrong secret" (per Q-8); both surface as `code: invalid_credential` to remove an existence-leak channel.

## Forward references

- `WEM-217` (sealed at-rest token storage on agent hosts) — defers the agent's bearer token storage from `~/.hermes/locksmith.token` mode 0600 to OS-keychain / systemd-creds equivalents.
- `WEM-218` (1Password Connect integration) — alternate distribution path for operator credentials and per-agent tokens.
- `WEM-219` (mTLS as feature-flagged auth alternative) — make `auth_mode: mtls`/`both` first-class with end-to-end smoke coverage in the layer8-proxy stack.
- `WEM-235` (RateLimiter) — first emitter for `AuthError::RateLimited`; the wire envelope is already in place (see TS-16 in `tests/auth.rs`).
