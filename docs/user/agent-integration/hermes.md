# Routing Hermes through layer8-proxy

`hermes-agent` (Nous Research) integrates with layer8-proxy via a
provider-config block in its YAML configuration. **No hermes code
changes required** — hermes already supports per-provider `base_url`
and `api_key` overrides, which is exactly the surface locksmith needs.

This is the ship-critical agent integration recipe.

## Prerequisites

- A running layer8-proxy v1.0.0 stack (see
  [layer8-proxy/docs/user/getting-started.md](https://github.com/SentientSwarm/layer8-proxy/blob/main/docs/user/getting-started.md)).
- An agent registered in locksmith with `anthropic` (and any other
  providers hermes will call) in its allowlist:
  ```bash
  locksmith agent register --name hermes-mini-m1 \
      --allowlist anthropic,openai,lmstudio,ollama,tavily,github
  ```
- The bearer token from `agent register` saved on the hermes host
  (conventionally at `~/.hermes/locksmith.token`, mode 0600).
- Hermes installed and runnable on the agent host
  (`pip install hermes-agent` or `uv venv` per the upstream docs).

## Two integration paths

There are two equally valid ways to wire hermes through locksmith.
Both produce the same wire effect — hermes calls land on locksmith
with the per-agent bearer, and locksmith injects the real provider
key.

### Path A — hermes provider-config (recommended)

Configure hermes' provider routing directly in `~/.hermes/config.yaml`
(or wherever your hermes config lives). Locksmith takes the place of
the upstream provider:

```yaml
# ~/.hermes/config.yaml
providers:
  anthropic:
    base_url: http://layer8.lan:9200/api/anthropic
    api_key: "${LOCKSMITH_TOKEN}"
  openai:
    base_url: http://layer8.lan:9200/api/openai
    api_key: "${LOCKSMITH_TOKEN}"
  lmstudio:
    base_url: http://layer8.lan:9200/api/lmstudio
    api_key: "${LOCKSMITH_TOKEN}"
  custom:
    base_url: http://layer8.lan:9200/api/ollama
    api_key: "${LOCKSMITH_TOKEN}"
    model_alias: ollama
```

Then export the bearer in hermes' env at launch:

```bash
export LOCKSMITH_TOKEN="$(cat ~/.hermes/locksmith.token)"
hermes
```

This is **the recommended path** because hermes' provider taxonomy
already understands these names — model lookups (`anthropic/claude-...`)
just work.

### Path B — `*_BASE_URL` env vars (SDK-level)

Some hermes paths talk directly to provider SDKs (Anthropic SDK, OpenAI
SDK) which honor standard env-var conventions:

```bash
export LOCKSMITH_TOKEN="$(cat ~/.hermes/locksmith.token)"
export ANTHROPIC_BASE_URL="http://layer8.lan:9200/api/anthropic"
export ANTHROPIC_API_KEY="$LOCKSMITH_TOKEN"
export OPENAI_BASE_URL="http://layer8.lan:9200/api/openai"
export OPENAI_API_KEY="$LOCKSMITH_TOKEN"
hermes
```

Use this for SDK-bypass paths (image generation, embeddings) that
don't go through the main provider config.

In practice you'll want **both A and B** active for full coverage —
provider-config for the conversational hot path, env vars for SDK
sub-clients.

## Step-by-step setup (hermes-site flow)

This mirrors the canonical `hermes-site` repo pattern — use it
as a template even if you're rolling your own deployment.

### 1. Create the hermes-site directory layout

```bash
mkdir -p ~/hermes-site/hermes
cd ~/hermes-site
```

### 2. Write `site.cfg`

```bash
cat > site.cfg <<'EOF'
# Site identity for the agent host.
site_name=mini-m1
host=$(hostname)

# Endpoint of the layer8-proxy stack.
#   Same-host topology:    http://127.0.0.1:9200
#   Neutral-host topology: http://layer8.lan:9200  (or whatever DNS / IP)
#
# Used by hermes/hermes.config.yaml for provider base_url interpolation.
layer8_endpoint=http://127.0.0.1:9200
EOF
```

### 3. Write the hermes config template

```bash
cat > hermes/hermes.config.yaml.tmpl <<'EOF'
# Hermes per-host config TEMPLATE. Renders to hermes.config.yaml via
# launch-hermes.sh on each launch. ${layer8_endpoint} comes from the
# sibling site.cfg; ${LOCKSMITH_TOKEN} stays literal so hermes does
# its own load-time substitution from the env var.

providers:
  anthropic:
    base_url: ${layer8_endpoint}/api/anthropic
    api_key: "${LOCKSMITH_TOKEN}"
  openai:
    base_url: ${layer8_endpoint}/api/openai
    api_key: "${LOCKSMITH_TOKEN}"
  lmstudio:
    base_url: ${layer8_endpoint}/api/lmstudio
    api_key: "${LOCKSMITH_TOKEN}"
  ollama-cloud:
    base_url: ${layer8_endpoint}/api/ollama
    api_key: "${LOCKSMITH_TOKEN}"

# Hermes' alignment / prompt-guard / code-shield scanners. Disabled
# by default in this template — locksmith's lf-scan kind=infra service
# already runs at the network boundary. Operators who want hermes-side
# in-process scanning AS WELL can enable them here.
scanners:
  alignment_check:
    enabled: false
  prompt_guard:
    enabled: false                  # owned by network-boundary plane (lf-scan today)
  code_shield:
    enabled: false                  # same reasoning
EOF
```

### 4. Install the bearer token

```bash
mkdir -p ~/.hermes
chmod 700 ~/.hermes
# Paste the bearer from `locksmith agent register --name hermes-mini-m1 ...`:
cat > ~/.hermes/locksmith.token <<'EOF'
lk_yN2vR6jFKNYfIwNjFU2MSA.1TJlTmOgmswZYZx_aQHyjaNiugeJjudytNPFJgT9aqM
EOF
chmod 600 ~/.hermes/locksmith.token
```

### 5. Write `launch-hermes.sh`

```bash
cat > launch-hermes.sh <<'EOF'
#!/usr/bin/env bash
# launch-hermes.sh — render the hermes config from the template,
# load the locksmith bearer, exec hermes.

set -euo pipefail

SITE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEMPLATE="$SITE_DIR/hermes/hermes.config.yaml.tmpl"
RENDERED="$SITE_DIR/hermes/hermes.config.yaml"
SITE_CFG="$SITE_DIR/site.cfg"

[[ -f "$TEMPLATE" ]] || { echo "ERROR: $TEMPLATE not found"; exit 1; }
[[ -f "$SITE_CFG" ]]  || { echo "ERROR: $SITE_CFG not found"; exit 1; }

# shellcheck source=/dev/null
. "$SITE_CFG"
[[ -n "${layer8_endpoint:-}" ]] \
    || { echo "ERROR: layer8_endpoint not set in $SITE_CFG"; exit 1; }

# Render the template — only ${layer8_endpoint} expands; ${LOCKSMITH_TOKEN}
# stays literal so hermes does its own load-time env-var substitution.
export layer8_endpoint
envsubst '${layer8_endpoint}' < "$TEMPLATE" > "$RENDERED"

TOKEN_FILE="${LOCKSMITH_TOKEN_FILE:-$HOME/.hermes/locksmith.token}"
[[ -f "$TOKEN_FILE" ]] || {
    echo "ERROR: locksmith bearer not found at $TOKEN_FILE"
    echo "       Get one from your operator: locksmith agent register --name $(hostname)"
    exit 1
}

LOCKSMITH_TOKEN=$(< "$TOKEN_FILE")
export LOCKSMITH_TOKEN

# Also export *_BASE_URL env vars for any SDK sub-paths hermes uses.
export ANTHROPIC_BASE_URL="$layer8_endpoint/api/anthropic"
export ANTHROPIC_API_KEY="$LOCKSMITH_TOKEN"
export OPENAI_BASE_URL="$layer8_endpoint/api/openai"
export OPENAI_API_KEY="$LOCKSMITH_TOKEN"

# Point hermes at the rendered config + exec.
exec hermes --config "$RENDERED" "$@"
EOF
chmod +x launch-hermes.sh
```

### 6. Verify

Start hermes:

```bash
./launch-hermes.sh
```

In a separate terminal, verify the proxy is seeing hermes' calls:

```bash
# On the locksmith host:
LOCKSMITH_OP_TOKEN="lkop_..."
docker exec -e LOCKSMITH_OP_TOKEN="$LOCKSMITH_OP_TOKEN" layer8-locksmith \
    /usr/local/bin/locksmith audit query \
    --since-ms $(($(date +%s) * 1000 - 300000)) \
    --tool anthropic \
    --format json | jq '.[] | {ts: .ts_ms, agent: .agent_public_id, tool, status, auth_mode: .details.auth_mode}'
```

You should see hermes' calls landing as `proxy_request` rows with
the agent's `public_id` matching what locksmith printed at registration.

## Network topology

### Same-host (hermes + locksmith on one Mac)

```
hermes (host process)
    ↓ http://127.0.0.1:9200/api/anthropic/...
layer8-locksmith (Docker container, port 9200 bound to localhost)
    ↓ HTTP CONNECT through pipelock
api.anthropic.com
```

`layer8_endpoint=http://127.0.0.1:9200` in `site.cfg`.

### Neutral-host (hermes on laptop, locksmith on a server)

```
hermes (laptop)
    ↓ http://layer8.lan:9200/api/anthropic/...
layer8-locksmith (server, port 9200 bound to 0.0.0.0 with TLS recommended)
    ↓ HTTP CONNECT through pipelock
api.anthropic.com
```

`layer8_endpoint=http://layer8.lan:9200` (or whatever DNS / IP the
laptop reaches the server at).

For production neutral-host setups, **enable mTLS on the agent
listener** (`listen.auth_mode: mtls`) so hermes presents a client cert
in addition to / instead of the bearer.

## Per-agent topology (multiple hermes instances)

When running multiple hermes instances on one host (different users,
isolated sessions), register one locksmith agent per instance:

```bash
docker exec layer8-locksmith /usr/local/bin/locksmith agent register \
    --name hermes-alice --allowlist anthropic,openai,tavily
docker exec layer8-locksmith /usr/local/bin/locksmith agent register \
    --name hermes-bob   --allowlist anthropic,lmstudio
```

Each gets its own bearer, its own ACL, its own audit trail. Per-user
hermes sites then reference the user-specific token file.

For Docker-compose multi-agent layouts (one container per hermes user),
see `hermes-site/docker-compose.yml` (planned at v1.1.0 / WEM-265-268)
which threads a per-agent token into each service via injected env.

## OAuth providers (codex, copilot, etc.)

For OAuth-flow providers (`codex` for ChatGPT Plus subscriptions,
`copilot` for GitHub Copilot, `anthropic-oauth`, `google-gemini-cli`,
`qwen-cli`):

1. Operator side: ensure `LOCKSMITH_OAUTH_SEALING_KEY` is set in the
   locksmith container's env.
2. Operator side: run the provider's own OAuth flow once to get a
   refresh token, then bootstrap:
   ```bash
   docker exec layer8-locksmith /usr/local/bin/locksmith oauth bootstrap codex \
       --refresh-token "$(get-refresh-token-via-providers-flow)"
   ```
3. Hermes side: route through locksmith just like any other provider.
   The `codex` registration is in the seed catalog (kind=model);
   reference it from your hermes config:
   ```yaml
   providers:
     openai-codex:
       base_url: ${layer8_endpoint}/api/codex
       api_key: "${LOCKSMITH_TOKEN}"
   ```

Locksmith handles the OAuth dance internally — refresh tokens are
sealed at rest and refreshed transparently. Hermes never sees the
OAuth machinery.

## Verifying the integration

A working hermes ↔ layer8-proxy ↔ Anthropic flow exhibits all of:

| Check | What it proves |
|---|---|
| Hermes starts without errors | provider config + bearer load OK |
| One conversation completes (e.g., `hermes "say hi"`) | full proxy chain works |
| Audit row with `tool=anthropic`, `status=200`, `auth_method=bearer`, `details.auth_mode=header` | proxy correctly authenticated, ACL'd, injected creds |
| `agent_public_id` in audit matches your registered agent | identity threading is right |
| `/api/openai/...` call (if openai NOT in allowlist) → 403 `tool_not_allowed` | ACL deny path works |

Run all five for confidence; the operator-facing
[layer8-proxy/docs/user/troubleshoot.md](https://github.com/SentientSwarm/layer8-proxy/blob/main/docs/user/troubleshoot.md)
covers the failure modes when one of them goes wrong.

## Migrating from a direct-API hermes deployment

If you have hermes running today directly against Anthropic / OpenAI
(no proxy):

1. Stand up a layer8-proxy stack (operator side).
2. Move provider keys from hermes' `.env` to the layer8-proxy-site
   `.env` (operator side). Hermes no longer needs them.
3. Register a locksmith agent for hermes (operator side).
4. Install the bearer at `~/.hermes/locksmith.token` (agent side).
5. Add the `providers:` block (path A) AND/OR `*_BASE_URL` env vars
   (path B) to hermes' config (agent side).
6. Restart hermes. Verify against the audit log.
7. Once you're confident: remove the cleartext provider keys from
   hermes' env / `.env`. The agent process never sees them again.

The migration is non-disruptive — hermes can run direct AND through
locksmith in parallel during cutover (different config files /
profiles).

## Limitations (v1.0)

- **Streaming**: works natively. SSE chat-completion streams pass
  through with ≤100 ms first-byte added latency.
- **Image generation, embeddings**: route via the SDK-level
  `*_BASE_URL` env vars (path B). Provider-config doesn't cover all
  hermes SDK sub-clients in v1.0.
- **Hermes' alignment_check scanner**: independent of layer8-proxy's
  lf-scan. You can run both, one, or neither. Most operators run
  lf-scan at the proxy boundary and disable hermes-side in-process
  scanners.
- **Tool registration auto-derivation**: hermes' tool catalog is
  hermes-side; locksmith's is locksmith-side. A v0.3+ enhancement
  will make hermes auto-discover from locksmith's `/tools` and
  `/models`. v1.0 requires manual registration on both sides.

## See also

- [`openclaw.md`](openclaw.md) — sister recipe for openclaw.
- [`wire-contract.md`](wire-contract.md) — what your agent actually
  sees on the wire.
- [`../concepts/agent-identity-and-acl.md`](../concepts/agent-identity-and-acl.md)
  — bearer + ACL semantics.
- [`layer8-proxy/docs/user/getting-started.md`](https://github.com/SentientSwarm/layer8-proxy/blob/main/docs/user/getting-started.md)
  — operator-side deploy.
