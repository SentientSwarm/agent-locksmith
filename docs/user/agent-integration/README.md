# Agent integration

Documentation for **agent developers** wiring an agent (hermes, openhands, custom) into a layer8-proxy deployment.

Current entry points:

- [Native MCP lifecycle](native-mcp.md) — authenticated2025-11-25 sessions with no callable tools.
- [HTTP services](http-services.md) — construct authorized service calls from discovery.

- `skill-reference.md` — `/skill` endpoint contract (agentskills.io format), unauthenticated vs personalized variants.
- `wire-contract.md` — endpoints, auth header shape, request/response envelopes, error codes.
- `examples/` — curl + language-specific recipes for common operations.
