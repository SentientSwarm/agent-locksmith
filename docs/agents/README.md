# Agent integration

For **agent developers** wiring an agent (Hermes, OpenClaw or your own) into
a Locksmith deployment. An agent needs only its Locksmith token and the
Locksmith URL.

- [HTTP services](http-services.md): build authorized service calls from
  discovery.
- [Native MCP](native-mcp.md): authenticated 2025-11-25 sessions with finite
  reviewed tools.
- [Compact native MCP](compact-mcp.md): the compact path, when an operator
  enables it.
- [Hermes](hermes.md) and [OpenClaw](openclaw.md): provider configuration.
- Examples in [curl](examples/curl.md), [Python](examples/python.md) and
  [TypeScript](examples/typescript.md).

Reference pages:

- [Wire contract](../reference/wire-contract.md): endpoints, headers, error
  codes and streaming.
- [`/skill` reference](../reference/skill-reference.md): generic and
  personalized forms.
- [Error envelope](../reference/error-envelope.md): the JSON error shape.
