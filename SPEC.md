# Secure Agent Proxy (SAP) — Technical Specification

## Overview

A Rust proxy that sits between AI agents and external services. It injects
credentials, enforces access policies, and provides tool discovery — so the
agent never sees API keys or secrets.

**Binary name:** `sap`

**Repository:** `github.com/jxstanford/secure-agent-proxy`

---

## Architecture

```
                          ┌──────────────────────┐
                          │   secure-agent-proxy  │
                          │        (sap)          │
Agent ──HTTP──►           │                       │
              ├──► /tools │  discovery            │
              ├──► /api/* │  REST credential inj. │──► Pipelock ──► internet
              ├──► /mcp/* │  MCP bridge           │──► local MCP servers
              ├──► /a2a/* │  A2A forwarding       │──► peer agents
              │           │                       │
              │           │  ┌─────────────────┐  │
              │           │  │ scanner sidecar  │  │  (future: M1)
              │           │  │ PromptGuard,     │  │
              │           │  │ CodeShield       │  │
              │           │  └─────────────────┘  │
              │           └──────────────────────┘
              │
              └──► /llm/* │  inference routing     │──► LAN / cloud models
                          │  (future: M1)          │
```

The proxy listens on a single port (default 9200). All agent traffic routes
through it. Credentials are loaded at startup from config; the agent receives
`not-required` or empty strings for any API key fields.

For cloud-bound requests, SAP forwards through Pipelock (HTTP CONNECT proxy)
for egress control and DLP scanning. Pipelock remains the network-layer
enforcement point.

---

## Milestones

### M0 — Tool API Proxy + Discovery (net-new)

The core value: credential injection for tool APIs with a discovery endpoint.

**Scope:**

1. **Config loading**
   - YAML config file (see Config Format below)
   - Credentials from environment variables (`${VAR_NAME}` expansion)
   - Conditional tool activation (missing/empty credentials = tool not registered)
   - Hot-reload on SIGHUP

2. **REST API proxying** (`/api/{tool_name}/{path}`)
   - Route requests to upstream by tool name prefix
   - Strip agent-sent auth headers
   - Inject configured credentials (header, query param, or basic auth)
   - Forward through Pipelock for cloud-bound requests
   - Pass-through for any HTTP method (GET, POST, PUT, DELETE, PATCH)
   - Configurable timeout per tool

3. **Tool discovery** (`GET /tools`)
   - Returns catalog of active tools with name, type, description, base path
   - Only lists tools with valid credentials configured
   - JSON response, stable schema

4. **Health endpoint** (`GET /health`)
   - Returns status, list of active tools, uptime

5. **Logging + telemetry**
   - Structured JSON logging to file + stdout
   - Request logging: tool name, path, status, duration
   - Optional OTLP metrics export (request counts, durations per tool)
   - Credential values never logged

6. **Security**
   - Credentials stored in `secrecy::SecretString` (zeroized on drop)
   - No credential in any log output, error message, or HTTP response
   - Optional auth for inbound requests (bearer token from agent/gateway)

**Out of scope for M0:**
- MCP bridging
- A2A forwarding
- Inference/LLM routing
- Budget enforcement
- Replacing Pipelock or LlamaFirewall

---

### M1 — Inference Routing + Scanner Integration (replace LlamaFirewall proxy)

Absorb LlamaFirewall's proxy layer. The Python scanning components become a
standalone sidecar service with an HTTP API.

**Scope:**

1. **Inference routing** (`/llm/{provider_name}/{path}`)
   - Multi-upstream routing by provider prefix
   - Credential injection (same mechanism as tool APIs)
   - Support both OpenAI and Anthropic API formats
   - Streaming response pass-through
   - `anthropic-version` header injection for Anthropic endpoints

2. **Scanner sidecar integration**
   - Call scanner sidecar via HTTP before forwarding (input scan)
   - Call scanner sidecar on response (output scan)
   - Configurable per-provider: scan enabled/disabled
   - Fail-open on scanner timeout/error (configurable)
   - Block response: return 403 with reason

3. **Scanner sidecar** (separate Python service)
   - `POST /scan` accepts `{role, content}`, returns `{decision, score, reason}`
   - Loads PromptGuard and CodeShield models
   - Stateless, horizontally scalable
   - Own systemd service, own venv

4. **Unified config**
   - Tools and inference endpoints in one config file
   - Credential injection uses same mechanism for both

**Deprecates:** `llamafirewall_proxy.py.j2` (the Jinja-templated Python proxy)

---

### M2 — Budget Enforcement

Per-provider spend tracking and enforcement, unified across inference and
tool APIs.

**Scope:**

1. **Cost tracking**
   - Per-provider token counting from response `usage` blocks
   - OpenAI and Anthropic token field name handling
   - Streaming usage extraction (parse final SSE chunk)
   - Inject `stream_options.include_usage` for OpenAI providers
   - Cost calculation from configurable per-1M-token rates

2. **Budget gate**
   - Pre-request budget check; return 429 when exhausted
   - Configurable monthly limit per provider (with global default)
   - Calendar-month reset (UTC)

3. **State persistence**
   - JSON state file, atomic writes
   - Survives restarts, resets on month boundary

4. **Budget API** (`GET /budget`)
   - Per-provider spend, limit, remaining, exhausted status
   - Current month

5. **Tool API budgets** (stretch)
   - Per-request cost tracking for metered tool APIs
   - Configurable cost-per-request for tools without token-based billing

---

### M3 — MCP Bridging

Bridge MCP servers through SAP so the agent accesses MCP tools with
credential isolation.

**Scope:**

1. **MCP server lifecycle**
   - Spawn STDIO-based MCP servers as child processes
   - Connect to SSE/HTTP-based MCP servers
   - Health checking and automatic restart
   - Graceful shutdown

2. **MCP tool proxying** (`POST /mcp/{server_name}/call`)
   - JSON-RPC bridge: accept HTTP POST, translate to MCP protocol
   - Tool call routing to correct server
   - Response translation back to HTTP

3. **Discovery integration**
   - MCP server tools appear in `GET /tools` response
   - Tool schemas (parameters, descriptions) included
   - Auto-refresh on MCP server reconnect

4. **Credential injection for MCP**
   - Inject env vars into spawned STDIO server processes
   - Inject auth headers for HTTP-based MCP servers

---

### M4 — A2A Forwarding

Agent-to-agent communication with credential injection.

**Scope:**

1. **A2A routing** (`/a2a/{peer_name}/{path}`)
   - Forward requests to peer agent gateways
   - Credential injection (gateway auth tokens)
   - Timeout and retry configuration

2. **Discovery integration**
   - Peers appear in `GET /tools` with type `a2a`

---

### M5 — Replace Pipelock (future, evaluate)

Absorb Pipelock's network-layer functionality. Evaluate whether this makes
sense or if Pipelock should remain separate.

**Would include:**
- CONNECT tunnel proxying
- Domain allowlist/blocklist
- DLP scanning (secret patterns, entropy analysis)
- SNI verification
- Tool chain detection
- nftables `skuid` integration (run as dedicated system user)

**Decision criteria:** Only pursue if the operational benefit of one fewer
service outweighs the complexity of combining network-layer and
application-layer proxying in one binary.

---

## Config Format

```yaml
# /etc/sap/config.yaml

listen:
  host: "127.0.0.1"
  port: 9200

# Optional auth for inbound requests from agent/gateway
inbound_auth:
  mode: "bearer"                    # none | bearer
  token: "${SAP_INBOUND_TOKEN}"

# Pipelock proxy for cloud-bound requests
egress_proxy: "http://127.0.0.1:8888"

# OTLP telemetry (optional)
telemetry:
  enabled: true
  otlp_endpoint: "http://127.0.0.1:4318"
  service_name: "secure-agent-proxy"

logging:
  level: "info"                     # debug | info | warn | error
  file: "/var/log/sap/proxy.log"

# ── Tool APIs ──────────────────────────────────────────────
tools:
  - name: "github"
    description: "GitHub REST API"
    upstream: "https://api.github.com"
    cloud: true                     # route through egress_proxy
    auth:
      header: "Authorization"
      value: "Bearer ${GITHUB_TOKEN}"
    timeout_seconds: 30

  - name: "tavily"
    description: "Tavily web search"
    upstream: "https://api.tavily.com"
    cloud: true
    auth:
      header: "x-api-key"
      value: "${TAVILY_API_KEY}"
    timeout_seconds: 15

  - name: "firecrawl"
    description: "Firecrawl web scraping"
    upstream: "https://api.firecrawl.dev"
    cloud: true
    auth:
      header: "Authorization"
      value: "Bearer ${FIRECRAWL_API_KEY}"
    timeout_seconds: 60

# ── Inference (M1) ─────────────────────────────────────────
# inference:
#   - name: "anthropic"
#     description: "Claude Haiku 4.5"
#     upstream: "https://api.anthropic.com/v1"
#     cloud: true
#     api_type: "anthropic"
#     auth:
#       header: "x-api-key"
#       value: "${ANTHROPIC_API_KEY}"
#     scan: true
#     budget:
#       monthly_usd: 50.00
#       cost_per_1m_input: 1.00
#       cost_per_1m_output: 5.00

# ── MCP Servers (M3) ───────────────────────────────────────
# mcp:
#   - name: "filesystem"
#     description: "Sandboxed file access"
#     transport: "stdio"
#     command: "npx"
#     args: ["@modelcontextprotocol/server-filesystem", "/workspace"]
#     env:
#       HOME: "/home/openclaw"

# ── A2A Peers (M4) ─────────────────────────────────────────
# a2a:
#   - name: "peer-agent"
#     description: "evo-x2-2 agent"
#     upstream: "https://192.168.50.21:18789"
#     auth:
#       header: "Authorization"
#       value: "Bearer ${PEER_AGENT_TOKEN}"
```

---

## API Reference

### `GET /health`

```json
{
  "status": "ok",
  "uptime_seconds": 3600,
  "tools": ["github", "tavily", "firecrawl"],
  "version": "0.1.0"
}
```

### `GET /tools`

```json
{
  "tools": [
    {
      "name": "github",
      "type": "api",
      "path": "/api/github",
      "description": "GitHub REST API"
    },
    {
      "name": "tavily",
      "type": "api",
      "path": "/api/tavily",
      "description": "Tavily web search"
    }
  ]
}
```

### `ANY /api/{tool_name}/{path}`

Proxied to upstream with credential injection. Returns upstream response
as-is (status code, headers, body).

### Error responses

```json
{"error": {"message": "Unknown tool: foo", "type": "not_found"}}           // 404
{"error": {"message": "Tool not configured: github", "type": "disabled"}}  // 503
{"error": {"message": "Upstream timeout", "type": "timeout"}}              // 504
```

---

## Build + Release

- **Language:** Rust (2024 edition)
- **Async runtime:** tokio
- **HTTP:** axum + hyper
- **Config:** serde + serde_yaml
- **Secrets:** secrecy crate (SecretString, zeroize on drop)
- **Telemetry:** opentelemetry + opentelemetry-otlp
- **HTTP client:** reqwest (with proxy support)
- **Logging:** tracing + tracing-subscriber (JSON output)
- **Binary:** `sap`
- **Targets:** `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`
- **CI:** GitHub Actions — build, test, release binaries
- **License:** Apache-2.0

---

## Integration with openclaw-deploy

New Ansible role `roles/sap/` in openclaw-deploy:

```
roles/sap/
├── tasks/main.yml          # install binary, write config, systemd
├── templates/
│   ├── sap.yaml.j2         # config from group_vars
│   └── sap.service.j2      # systemd unit
└── handlers/main.yml       # restart sap
```

Config driven by `group_vars/agent_hosts/main.yml`:

```yaml
sap:
  enabled: true
  listen_port: 9200
  tools:
    - name: "github"
      upstream: "https://api.github.com"
      api_key: "{{ vault_github_token | default('') }}"
      api_key_header: "Authorization"
      api_key_prefix: "Bearer"
      description: "GitHub REST API"
    # ...
```

Same conditional activation pattern as inference endpoints: empty key = tool
not registered.
