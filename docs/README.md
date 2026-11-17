# Locksmith documentation

Locksmith holds the credentials your agents use. An agent authenticates to
Locksmith with its own token or client certificate, and Locksmith calls the
upstream service with the account an operator selected for that agent. The
agent never sees the upstream credential.

This page is the entry point. Pick the section for what you are doing.

## Operators

Start with the guide. Each journey is a task done end to end, and the UAT
runs its commands as written.

1. [Install and first run](guide/01-install.md)
2. [Connect an HTTP service](guide/02-http-service.md)
3. [Keep credentials in Locksmith](guide/03-credential-custody.md)
4. [Enrol agents](guide/04-enrol-agents.md)
5. [Connect an MCP service](guide/05-mcp-service.md)
6. [Connect an OAuth service](guide/06-oauth-service.md)
7. [Audit and monitor](guide/07-audit-and-monitor.md)
8. [Day-two operations](guide/08-operate.md)

The [guide index](guide/README.md) lists its conventions and how it is tested.

### Deploy

Locksmith is two binaries, `locksmithd` (the daemon) and `locksmith` (the
CLI). This repository ships two ways to run the daemon:

- **Native systemd service.** A hardened unit template is in
  [`dist/systemd/`](../dist/systemd/locksmith.service.template).
- **Incus edge.** [Edge packaging](operator/edge-packaging.md) renders
  hardened systemd units for Incus system containers from a site file you
  keep privately (`dist/edge/`).

Outbound traffic for `egress: proxied` routes is set by `egress.mode` in the
config. `pipelock` sends those routes through the egress proxy named by
`egress_proxy`. `external` sends them directly and relies on your network to
enforce egress. See [egress and inspection](concepts/egress-and-inspection.md).

### Task how-tos

The [operator how-tos](operator/README.md) are grouped by subject: HTTP
connections, integration definitions, native MCP, OAuth, Slack, custody and
recovery, edge packaging, and the feature runbooks.

## Concepts

The [concept pages](concepts/README.md) explain how Locksmith works: the
[trust boundary](concepts/trust-boundary.md),
[agent identity and ACL](concepts/agent-identity-and-acl.md), per-agent
credentials, OAuth, egress and the [threat model](concepts/threat-model.md).

## Agent developers

An agent needs only its Locksmith token and the Locksmith URL.

- [Wire contract](reference/wire-contract.md): endpoints,
  headers, error codes and streaming.
- [HTTP services](agents/http-services.md): build calls
  from typed discovery.
- [Native MCP](agents/native-mcp.md) and
  [compact native MCP](agents/compact-mcp.md).
- [`/skill` reference](reference/skill-reference.md).
- Recipes for [Hermes](agents/hermes.md) and
  [OpenClaw](agents/openclaw.md).
- Examples in [curl](agents/examples/curl.md),
  [Python](agents/examples/python.md) and
  [TypeScript](agents/examples/typescript.md).

## Reference

- [CLI reference](reference/cli-reference.md): every `locksmith` subcommand and
  flag.
- [Wire contract](reference/wire-contract.md): the
  agent-facing HTTP surface.
- [Error envelope](reference/error-envelope.md): the JSON error shape
  and its codes.
- [Architecture](concepts/architecture.md): daemon composition, request flow
  and where state lives.

## Change notes

Read these before upgrading an existing installation.

- [Explicit account bindings](changes/explicit-account-bindings.md)
- [Explicit HTTP grants and activation](changes/explicit-http-grants.md)
- [HTTP connector onboarding](changes/connector-onboarding.md)
- [Integration definition activation](changes/integration-definitions.md)
- [Native MCP lifecycle and migration](changes/native-mcp.md)
- [Upgrade to finite HTTP grants and explicit accounts](concepts/migrating-account-bindings.md)

## Contributors

The repository [README](../README.md) covers building and testing.
Contributor documentation is in [`development/`](development/):

- [Branching and releases](development/branching.md)
- [Local review](development/review.md)
- [Local CI](development/local-ci.md) and the [QA suites](../qa/README.md)
- [Build identity](development/build-identity.md)
- [Content inspection](development/inspection.md)
- [Native MCP daemon boundary](development/native-mcp.md)

## Historical

These record earlier designs and plans. They do not describe current
behaviour; use the pages above instead.

- [`archive/v2/`](archive/v2/): the 2.x engineering spec, PRD and handoff.
- [`archive/design/`](archive/design/): design notes for the explicit account and HTTP
  grant work.
- [`archive/plans/`](archive/plans/): early implementation plans.
- [`archive/SPEC.md`](archive/SPEC.md): the original pre-v2 specification, kept for
  reference only.
