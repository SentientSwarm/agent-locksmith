# Routing OpenClaw through layer8-proxy

OpenClaw integrates with layer8-proxy via the standard
`*_BASE_URL` environment-variable convention used by the Anthropic
and OpenAI SDKs. **No openclaw code changes required.**

## Prerequisites

- A running layer8-proxy stack (see [layer8-proxy/docs/user/getting-started.md](../../../../layer8-proxy/docs/user/getting-started.md)).
- Operator has registered an agent for openclaw via `locksmith agent register --name openclaw-host1 --allowlist anthropic,openai,...`.
- Bearer token from the agent registration installed on the openclaw host.

## Configuration

Set the following environment variables on the openclaw host:

```bash
# Required: agent bearer token from `locksmith agent register`
export LOCKSMITH_TOKEN=lk_pid.secret-from-locksmith-output

# Route Anthropic calls via locksmith
export ANTHROPIC_BASE_URL=http://layer8.lan:9200/api/anthropic
export ANTHROPIC_API_KEY=$LOCKSMITH_TOKEN

# Route OpenAI calls via locksmith
export OPENAI_BASE_URL=http://layer8.lan:9200/api/openai
export OPENAI_API_KEY=$LOCKSMITH_TOKEN

# OAuth providers (Phase F): operator runs `locksmith oauth bootstrap`
# once per provider; subsequent calls just need the bearer.
# Example for ChatGPT Plus subscription:
# export OPENAI_BASE_URL=http://layer8.lan:9200/api/codex
```

## How it works

OpenClaw's Anthropic / OpenAI SDK reads `*_BASE_URL` and `*_API_KEY` at
client construction (see `src/agents/cli-runner.spawn.test.ts` for the
canonical openclaw env-var conventions). When set, the SDK posts to the
configured base URL with the supplied key as the bearer.

In our setup, the bearer the SDK sends is the **agent's locksmith
token**, not the provider's API key. Locksmith:

1. Validates the bearer against the agent's registration.
2. Enforces the agent's `tool_allowlist` (e.g., does this openclaw
   instance have `anthropic` in its allowlist? if not → 403).
3. Strips the agent's `Authorization` / `x-api-key` headers (defense
   against agent override).
4. Injects the **provider's actual credentials** from `resolved_creds`
   (sealed at rest on the locksmith host).
5. Forwards to the upstream (`https://api.anthropic.com` etc.) and
   streams the response back.

The openclaw container never sees the provider's API key. It only ever
holds its own per-agent locksmith bearer.

## Multiple openclaw instances on one host

If you run multiple openclaw instances (different users, isolated
sessions), register one agent per instance:

```bash
locksmith agent register --name openclaw-alice --allowlist anthropic,openai
locksmith agent register --name openclaw-bob   --allowlist anthropic,tavily
```

Each gets its own bearer with its own ACL. Audit rows record
`agent_public_id` so you can correlate calls back to their owning
instance.

## Verifying the setup

```bash
# Should succeed (anthropic in allowlist)
curl -sS -X POST $ANTHROPIC_BASE_URL/v1/messages \
    -H "Authorization: Bearer $LOCKSMITH_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"model":"claude-3-haiku-20240307","max_tokens":10,"messages":[{"role":"user","content":"ping"}]}'

# Audit row should appear with auth_mode=header (or auth_mode=bearer
# depending on the registered AuthSpec) and the agent's public_id.
docker exec layer8-locksmith /usr/local/bin/locksmith audit query --since-ms $(($(date +%s) * 1000 - 60000)) --tool anthropic
```

## Migrating from openclaw-hardened

`openclaw-hardened` is the legacy Ansible-roles deployment path. It
predates layer8-proxy and bundles its own pipelock + provider auth.

To migrate:

1. Stand up a layer8-proxy stack (see `layer8-proxy/docs/user/getting-started.md`).
2. Move provider API keys from openclaw-hardened's `.env` into the
   layer8-proxy-site `.env`.
3. Register an openclaw agent in locksmith.
4. Set the `*_BASE_URL` + `LOCKSMITH_TOKEN` env vars on the openclaw
   host (replace `*_API_KEY` if it referenced the provider's actual key).
5. Restart openclaw.
6. Decommission openclaw-hardened's pipelock binary once you've
   confirmed all openclaw traffic flows through layer8-proxy.

The openclaw-hardened deployment can run alongside layer8-proxy during
the migration; they don't conflict (different ports, different
processes).

## Limitations (v1.0)

- **Provider list**: locksmith ships an 11-entry seed catalog at v1.0
  (anthropic, openai, openrouter, ai-gateway, ollama, lmstudio,
  tavily, github, duckduckgo, wikipedia, lf-scan) plus 5 OAuth
  providers (codex, copilot, anthropic-oauth, google-gemini-cli,
  qwen-cli). Other providers require operator-side
  `locksmith model put <name>` registration.
- **OAuth UX**: the v1.0 OAuth bootstrap flow is "operator obtains a
  refresh token via the provider's own CLI then runs `locksmith oauth
  bootstrap <name> --refresh-token <token>`". Interactive PKCE / device-
  code flows land in v1.1+.
- **Single network namespace**: openclaw and layer8-proxy don't need
  to be on the same Docker network. They communicate via LAN HTTP.
  If you do colocate them via Docker, make sure layer8-proxy's
  listen address is reachable from the openclaw container (typically
  via host networking or an explicit network alias).

## See also

- [`layer8-proxy/docs/user/getting-started.md`](../../../../layer8-proxy/docs/user/getting-started.md) — full deploy walkthrough.
- [`layer8-proxy/docs/user/add-an-agent.md`](../../../../layer8-proxy/docs/user/add-an-agent.md) — agent registration.
- [`agent-locksmith/docs/user/concepts/agent-identity-and-acl.md`](../concepts/agent-identity-and-acl.md) — per-agent bearer semantics.
- [`agents-stack/docs/spec/v0.2.0.md`](../../../../agents-stack/docs/spec/v0.2.0.md) — formal stack spec.
