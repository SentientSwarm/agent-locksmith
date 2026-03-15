# Agent Locksmith

A Rust proxy that sits between AI agents and external services. It injects credentials, enforces access policies, and provides tool discovery — so the agent never sees API keys or secrets.

## Why?

AI agents need access to external tools (GitHub, search APIs, web scrapers) but shouldn't hold API keys directly. Locksmith acts as a credential-injecting reverse proxy:

- **Agent sends:** `POST /api/github/repos` (no auth header)
- **Locksmith forwards:** `POST https://api.github.com/repos` with `Authorization: Bearer <real-token>`

The agent discovers available tools via `GET /tools` and never sees the actual credentials.

## Features

- **Credential injection** — Configured per-tool auth headers injected into upstream requests
- **Tool discovery** — `GET /tools` returns catalog of active tools (only those with valid credentials)
- **Auth header stripping** — Agent-sent auth headers are stripped before forwarding
- **Conditional activation** — Tools with empty/missing credentials are automatically hidden
- **Egress proxy support** — Cloud-bound requests route through an HTTP CONNECT proxy (e.g., Pipelock)
- **Inbound auth** — Optional bearer token authentication for agent requests
- **Structured logging** — JSON-formatted logs via `tracing`, credentials never logged
- **Memory-safe secrets** — Credentials stored in `secrecy::SecretString` (zeroized on drop)
- **Hot-reload** — Config reloadable at runtime via ArcSwap

## Quick Start

### Build

```bash
cargo build --release
# Binary: target/release/locksmith
```

### Configure

```yaml
# /etc/locksmith/config.yaml
listen:
  host: "127.0.0.1"
  port: 9200

tools:
  - name: "github"
    description: "GitHub REST API"
    upstream: "https://api.github.com"
    cloud: true
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
```

Credentials use `${VAR_NAME}` syntax — resolved from environment variables at startup.

### Run

```bash
export GITHUB_TOKEN="ghp_..."
export TAVILY_API_KEY="tvly-..."
locksmith --config /etc/locksmith/config.yaml
```

## API

### `GET /health`

```json
{
  "status": "ok",
  "uptime_seconds": 3600,
  "tools": ["github", "tavily"],
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
    }
  ]
}
```

Only lists tools with valid (non-empty) credentials configured.

### `ANY /api/{tool_name}/{path}`

Proxied to the tool's upstream URL with credential injection. The upstream response is returned as-is (status code, headers, body).

```bash
# Agent calls Locksmith (no credentials needed):
curl http://localhost:9200/api/github/repos/octocat/hello-world

# Locksmith forwards to https://api.github.com/repos/octocat/hello-world
# with Authorization: Bearer <configured-token>
```

### Error Responses

```json
{"error": {"message": "Unknown tool: foo", "type": "not_found"}}           // 404
{"error": {"message": "Upstream timeout", "type": "timeout"}}              // 504
{"error": {"message": "Unauthorized", "type": "auth_error"}}               // 401
```

## Configuration Reference

```yaml
listen:
  host: "127.0.0.1"          # Bind address
  port: 9200                  # Bind port

# Optional: require bearer token from agents
inbound_auth:
  mode: "bearer"              # none | bearer
  token: "${LOCKSMITH_INBOUND_TOKEN}"

# Optional: route cloud-bound requests through egress proxy
egress_proxy: "http://127.0.0.1:8888"

logging:
  level: "info"               # debug | info | warn | error
  file: "/var/log/locksmith/proxy.log"

tools:
  - name: "github"            # URL prefix: /api/github/*
    description: "GitHub REST API"
    upstream: "https://api.github.com"
    cloud: true                # Route through egress_proxy
    auth:
      header: "Authorization"  # Header to inject
      value: "Bearer ${GITHUB_TOKEN}"  # Value (env var expanded)
    timeout_seconds: 30
```

### Conditional Activation

Tools with empty credential values are automatically excluded from discovery and routing:

```yaml
tools:
  - name: "tavily"
    upstream: "https://api.tavily.com"
    auth:
      header: "x-api-key"
      value: "${TAVILY_API_KEY}"    # If TAVILY_API_KEY is unset/empty,
                                     # this tool won't appear in /tools
```

Tools with no `auth` block are always active (no credentials required).

## Security

- Credentials stored in `secrecy::SecretString` — zeroized when dropped from memory
- Credentials never appear in log output, error messages, or HTTP responses
- Agent-sent `Authorization` and `x-api-key` headers are stripped before forwarding
- The configured auth header for each tool is also stripped to prevent agent override
- Optional inbound bearer auth protects all endpoints except `/health`

## Deployment

Locksmith is designed to run as a systemd service alongside tools like [Pipelock](https://github.com/luckyPipewrench/pipelock) for network-layer egress control.

```
Agent ──► Locksmith (:9200) ──► Pipelock (:8888) ──► Internet
              │
              └──► LAN services (direct)
```

For Ansible-based deployment, see the `roles/locksmith/` role in [openclaw-deploy](https://github.com/SentientSwarm/openclaw-deploy).

## Roadmap

| Milestone | Description | Status |
|-----------|-------------|--------|
| **M0** | Tool API proxy + discovery | Done |
| **M1** | Inference routing + scanner sidecar | Planned |
| **M2** | Per-provider budget enforcement | Planned |
| **M3** | MCP server bridging | Planned |
| **M4** | A2A agent forwarding | Planned |

See [SPEC.md](SPEC.md) for detailed milestone specifications.

## Development

```bash
# Run tests
cargo test

# Run with clippy
cargo clippy -- -D warnings

# Run with example config
GITHUB_TOKEN=test locksmith --config config.example.yaml
```

## Integration with openclaw-hardened

Locksmith is deployed as part of the
[openclaw-hardened](https://github.com/SentientSwarm/openclaw-hardened)
security stack. The `locksmith` Ansible role handles building the binary,
generating config from site variables, and managing the systemd service.

### Where Locksmith fits

```
Agent request (no auth)
  → Locksmith (injects credentials)
    → Pipelock (egress control + DLP scanning)
      → Internet (GitHub, Tavily, Firecrawl, etc.)
```

The agent sends requests to `http://localhost:9200/api/<tool>/...` without
any authentication headers. Locksmith injects the real credentials and
forwards the request. For cloud-bound tools, the request routes through
Pipelock for egress control.

### Ansible configuration

Tools are defined in site config under `locksmith.tools`:

```yaml
locksmith:
  enabled: true
  tools:
    - name: "github"
      description: "GitHub REST API"
      upstream: "https://api.github.com"
      cloud: true
      auth:
        header: "Authorization"
        value: "Bearer {{ vault_github_token }}"
    - name: "tavily"
      description: "Tavily search API"
      upstream: "https://api.tavily.com"
      cloud: true
      auth:
        header: "Authorization"
        value: "Bearer {{ vault_tavily_api_key }}"
```

See the
[site config schema](https://github.com/SentientSwarm/openclaw-hardened/blob/main/docs/site-config-schema.md)
for all Locksmith variables.

### Security properties

- Credentials stored in Ansible vault, injected at deploy time
- Agent never sees API keys — Locksmith strips agent-sent auth headers
- Locksmith process runs as the `openclaw` user
- Inbound authentication via bearer token (`vault_locksmith_inbound_token`)
- Memory-safe secrets via `secrecy::SecretString` (zeroized on drop)

## License

MIT — see [LICENSE](LICENSE).
