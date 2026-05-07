# curl recipes

Copy-paste ready curl invocations for every common locksmith
operation. Useful for shell-script integration, ad-hoc testing,
and as a Rosetta stone to whatever language you're using.

Set these once per shell session:

```bash
export LOCKSMITH_URL="http://layer8.lan:9200"   # your locksmith
export AGENT_TOKEN="lk_yN2v..."                  # your agent bearer
export OP_TOKEN="lkop_..."                       # operator token (admin paths)
```

## Health probes

```bash
# Liveness — should always 200 if daemon's up.
curl -sS "$LOCKSMITH_URL/livez"

# Readiness — 503 if any tool with auth has unresolved creds.
curl -sS "$LOCKSMITH_URL/readyz"

# Build metadata.
curl -sS "$LOCKSMITH_URL/version"
```

## Discovery (agent-authenticated)

```bash
# kind=tool catalog, filtered by your agent's allowlist.
curl -sS -H "Authorization: Bearer $AGENT_TOKEN" "$LOCKSMITH_URL/tools" | jq

# kind=model catalog.
curl -sS -H "Authorization: Bearer $AGENT_TOKEN" "$LOCKSMITH_URL/models" | jq

# Skill rendering (markdown).
curl -sS -H "Authorization: Bearer $AGENT_TOKEN" "$LOCKSMITH_URL/skill"
```

## Provider calls

### Anthropic

```bash
curl -sS -X POST "$LOCKSMITH_URL/api/anthropic/v1/messages" \
    -H "Authorization: Bearer $AGENT_TOKEN" \
    -H "anthropic-version: 2023-06-01" \
    -H "Content-Type: application/json" \
    -d '{
        "model": "claude-haiku-4-5",
        "max_tokens": 100,
        "messages": [{"role": "user", "content": "Say hi"}]
    }' | jq
```

### OpenAI

```bash
curl -sS -X POST "$LOCKSMITH_URL/api/openai/v1/chat/completions" \
    -H "Authorization: Bearer $AGENT_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
        "model": "gpt-4o-mini",
        "messages": [{"role": "user", "content": "Say hi"}]
    }' | jq
```

### LM Studio

```bash
curl -sS -X POST "$LOCKSMITH_URL/api/lmstudio/v1/chat/completions" \
    -H "Authorization: Bearer $AGENT_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
        "model": "qwen2.5-coder-32b",
        "messages": [{"role": "user", "content": "Say hi"}]
    }' | jq
```

### Tavily search

```bash
curl -sS -X POST "$LOCKSMITH_URL/api/tavily/search" \
    -H "Authorization: Bearer $AGENT_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"query": "what is layer8-proxy", "max_results": 3}' | jq
```

### GitHub

```bash
curl -sS "$LOCKSMITH_URL/api/github/repos/SentientSwarm/agent-locksmith" \
    -H "Authorization: Bearer $AGENT_TOKEN" | jq '{name, description, stargazers_count}'
```

### Streaming (Anthropic SSE)

```bash
curl -N -sS -X POST "$LOCKSMITH_URL/api/anthropic/v1/messages" \
    -H "Authorization: Bearer $AGENT_TOKEN" \
    -H "anthropic-version: 2023-06-01" \
    -H "Content-Type: application/json" \
    -d '{
        "model": "claude-haiku-4-5",
        "max_tokens": 200,
        "stream": true,
        "messages": [{"role": "user", "content": "count to 10"}]
    }'
```

`-N` disables curl's output buffering so you see chunks as they arrive.

## Operator paths (admin)

### Agent management

```bash
# List all agents.
curl -sS -H "Authorization: Bearer $OP_TOKEN" --unix-socket /var/run/locksmith/admin.sock \
    http://_/admin/operator/agents | jq

# Register a new agent.
curl -sS -X POST -H "Authorization: Bearer $OP_TOKEN" \
    -H "Content-Type: application/json" \
    --unix-socket /var/run/locksmith/admin.sock \
    -d '{"name":"hermes-laptop","allowlist":["anthropic","openai"]}' \
    http://_/admin/operator/agents | jq

# Revoke.
curl -sS -X POST -H "Authorization: Bearer $OP_TOKEN" \
    --unix-socket /var/run/locksmith/admin.sock \
    http://_/admin/operator/agents/<public_id>/revoke
```

For admin HTTPS instead of UDS, replace `--unix-socket /var/run/locksmith/admin.sock`
with the HTTPS URL + `--cacert ca.pem` for cert verification.

### Catalog management

```bash
# List models.
curl -sS -H "Authorization: Bearer $OP_TOKEN" --unix-socket /var/run/locksmith/admin.sock \
    http://_/admin/operator/models | jq

# Override a seed default.
curl -sS -X PUT -H "Authorization: Bearer $OP_TOKEN" \
    -H "Content-Type: application/json" \
    --unix-socket /var/run/locksmith/admin.sock \
    -d '{
        "upstream": "http://mac-server.lan:1234",
        "auth": {"kind":"bearer","env_var":"LM_STUDIO_API_KEY"}
    }' \
    http://_/admin/operator/models/lmstudio | jq

# Disable a seed default.
curl -sS -X DELETE -H "Authorization: Bearer $OP_TOKEN" \
    --unix-socket /var/run/locksmith/admin.sock \
    http://_/admin/operator/models/openrouter

# Re-enable.
curl -sS -X POST -H "Authorization: Bearer $OP_TOKEN" \
    --unix-socket /var/run/locksmith/admin.sock \
    http://_/admin/operator/models/openrouter/enable
```

### OAuth bootstrap

```bash
curl -sS -X POST -H "Authorization: Bearer $OP_TOKEN" \
    -H "Content-Type: application/json" \
    --unix-socket /var/run/locksmith/admin.sock \
    -d '{"refresh_token": "<paste-from-providers-oauth-flow>"}' \
    http://_/admin/operator/oauth/codex/bootstrap | jq

curl -sS -H "Authorization: Bearer $OP_TOKEN" --unix-socket /var/run/locksmith/admin.sock \
    http://_/admin/operator/oauth/codex | jq
```

### Audit query

```bash
SINCE_MS=$(($(date +%s) * 1000 - 3600000))   # last hour
curl -sS -H "Authorization: Bearer $OP_TOKEN" --unix-socket /var/run/locksmith/admin.sock \
    "http://_/admin/operator/audit?since_ms=$SINCE_MS&decision=denied" | jq
```

## Self-service (agent-authenticated)

```bash
# Show your agent state.
curl -sS -H "Authorization: Bearer $AGENT_TOKEN" --unix-socket /var/run/locksmith/admin.sock \
    http://_/admin/agent/status | jq

# Rotate your bearer (returns new token; old immediately invalidated).
curl -sS -X POST -H "Authorization: Bearer $AGENT_TOKEN" \
    --unix-socket /var/run/locksmith/admin.sock \
    http://_/admin/agent/rotate | jq
```

## Error envelope examples

What you'll see when things go wrong (each with the §4.7.9 envelope):

```bash
# No bearer:
curl -sS "$LOCKSMITH_URL/api/anthropic/v1/messages" -X POST -d '{}'
# {"error":{"type":"auth_error","code":"missing_credential","message":"missing credential"}}

# Bad bearer:
curl -sS -H "Authorization: Bearer lk_bad.bad" "$LOCKSMITH_URL/api/anthropic/v1/messages" -X POST -d '{}'
# {"error":{"type":"auth_error","code":"invalid_credential","message":"invalid credential"}}

# Tool not in allowlist:
curl -sS -H "Authorization: Bearer $AGENT_TOKEN" "$LOCKSMITH_URL/api/notin-allowlist/anything"
# {"error":{"type":"authz_error","code":"tool_not_allowed","message":"tool access denied"}}

# Tool doesn't exist:
curl -sS -H "Authorization: Bearer $AGENT_TOKEN" "$LOCKSMITH_URL/api/totally-fake/anything"
# {"error":{"type":"not_found","message":"Unknown tool: totally-fake"}}
```

## See also

- [wire-contract.md](../wire-contract.md) — formal endpoint reference.
- [hermes.md](../hermes.md), [openclaw.md](../openclaw.md) —
  agent-specific recipes.
