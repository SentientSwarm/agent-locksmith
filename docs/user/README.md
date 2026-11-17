# Locksmith user documentation

This tree documents how to run and use Locksmith. It reflects the latest
release and is not versioned by filename. For the overall map, including the
operator guide journeys and contributor documentation, start at the
[documentation entry point](../README.md).

## Audiences

- **Operators** run `locksmithd` and manage it with the `locksmith` CLI:
  register services and agents, select accounts, grant tools, audit.
  Start with the [guide journeys](../guide/README.md), then use the
  how-tos below.
- **Agent developers** connect an agent (Hermes, OpenClaw or your own) to a
  running Locksmith with the agent's own token.
- **Developers** evaluating Locksmith or embedding it in their own
  deployment can start with [getting started](getting-started.md).

## Get started and reference

| Doc | Topic |
|---|---|
| [getting-started.md](getting-started.md) | Build, mint an operator credential, register an agent, select an account and make a call on a disposable instance. |
| [cli-reference.md](cli-reference.md) | Every `locksmith` CLI subcommand and flag. |
| [architecture.md](architecture.md) | Daemon composition, request flow and what state lives where. |

## Deploy

| Doc | Topic |
|---|---|
| [operator/edge-packaging.md](operator/edge-packaging.md) | Run Locksmith (and optionally Pipelock and a classifier sidecar) as hardened systemd units in Incus containers, rendered from a private site file. |
| [concepts/egress-and-inspection.md](concepts/egress-and-inspection.md) | `egress.mode: pipelock` or `external`, brokered routes, TLS interception and content inspection. |

For a native install without containers, the hardened systemd unit template
is [`dist/systemd/locksmith.service.template`](../../dist/systemd/locksmith.service.template).

## Concepts (`concepts/`)

| Doc | Topic |
|---|---|
| [concepts/README.md](concepts/README.md) | Index of the concept pages. |
| [concepts/trust-boundary.md](concepts/trust-boundary.md) | Who holds which credential, and why. |
| [concepts/kind-taxonomy.md](concepts/kind-taxonomy.md) | The `model` / `tool` / `infra` registration kinds. |
| [concepts/agent-identity-and-acl.md](concepts/agent-identity-and-acl.md) | Per-agent bearer, allowlist and audit attribution. |
| [concepts/error-envelope.md](concepts/error-envelope.md) | The JSON error envelope and existence-leak avoidance. |
| [concepts/per-agent-credentials.md](concepts/per-agent-credentials.md) | Per-agent credential overrides and OAuth session labels; the single-grant trap. |
| [concepts/oauth-flow.md](concepts/oauth-flow.md) | OAuth bootstrap, refresh and the per-request path, including codex header and body fixups. |
| [concepts/egress-and-inspection.md](concepts/egress-and-inspection.md) | Egress modes, brokered routes, per-route CAs and the classifier gap. |
| [concepts/migrating-account-bindings.md](concepts/migrating-account-bindings.md) | Offline reviewed migration to finite HTTP grants and explicit accounts. |

## Operator how-tos (`operator/`)

### HTTP connections and accounts

| Doc | Topic |
|---|---|
| [operator/connector-onboarding.md](operator/connector-onboarding.md) | Validate a reference or customer HTTP service, grant a named agent, select its account and verify the receiving effect. |
| [operator/account-binding-troubleshooting.md](operator/account-binding-troubleshooting.md) | Error classes for explicit account access and how to repair them. |

### Integration definitions

| Doc | Topic |
|---|---|
| [operator/integration-definitions.md](operator/integration-definitions.md) | Immutable definitions, disabled exact pins and deliberate local customer activation. |
| [operator/customer-mcp-journey.md](operator/customer-mcp-journey.md) | From a customer definition to one deliberately granted MCP task for an agent. |

### Native MCP

| Doc | Topic |
|---|---|
| [operator/native-mcp.md](operator/native-mcp.md) | Native MCP lifecycle setup, current identity and upgrade requirements. |
| [operator/native-tool-review.md](operator/native-tool-review.md) | Observe, inspect and review native tools for an agent's account. |
| [operator/native-tool-grants.md](operator/native-tool-grants.md) | Grant or revoke finite reviewed native tools. |
| [operator/native-contract-policy.md](operator/native-contract-policy.md) | Choosing `finite-v1` or `finite-v2` contract policy. |
| [operator/native-context.md](operator/native-context.md) | Fixed native context and safe diagnosis. |
| [operator/native-oauth.md](operator/native-oauth.md) | Controlled OAuth accounts for native MCP. |
| [operator/hosted-linear.md](operator/hosted-linear.md) | The fixed hosted Linear OAuth profile and its offline twin. |

### OAuth

| Doc | Topic |
|---|---|
| [operator/custom-oauth.md](operator/custom-oauth.md) | Declared `custom-oauth-v1` contracts for preregistered services. |
| [operator/custom-oauth-workflow.md](operator/custom-oauth-workflow.md) | Activate and use a declared OAuth service. |
| [operator/custom-oauth-profile.example.json](operator/custom-oauth-profile.example.json) | Example declared profile (invented values). |
| [operator/oauth-account-response-v1.schema.json](operator/oauth-account-response-v1.schema.json) | JSON schema for OAuth account responses. |
| [operator/oauth-consent.md](operator/oauth-consent.md) | Controlled operator consent, owner-bound sealed custody and disconnect. |
| [operator/oauth-recovery.md](operator/oauth-recovery.md) | Uncertain refreshes, recovery and the 0013 upgrade. |
| [operator/oauth-capability-proof.md](operator/oauth-capability-proof.md) | Bounded OAuth refusal and lifecycle evidence. |

### Slack

| Doc | Topic |
|---|---|
| [operator/slack-oauth.md](operator/slack-oauth.md) | Confidential Slack OAuth accounts: profile, activation, consent and grants. |
| [operator/slack-oauth-lifecycle.md](operator/slack-oauth-lifecycle.md) | Renewal, retirement and upgrades. |
| [operator/slack-callback.md](operator/slack-callback.md) | Callback redirect setup and upgrade. |
| [operator/slack-identity-diagnostics.md](operator/slack-identity-diagnostics.md) | Identity response and safe diagnostics. |
| [operator/slack-token-diagnostics.md](operator/slack-token-diagnostics.md) | Token metadata diagnostics. |

### Custody and recovery

| Doc | Topic |
|---|---|
| [operator/sealed-state-recovery.md](operator/sealed-state-recovery.md) | Consistent snapshots, independent key recovery and quarantined restore. |
| [operator/1password-setup.md](operator/1password-setup.md) | Optional pattern (scripts not shipped): render deployment `.env` files from 1Password Environments. |

### Edge packaging

| Doc | Topic |
|---|---|
| [operator/edge-packaging.md](operator/edge-packaging.md) | Hardened systemd units in Incus containers, from a private site file. |

## Agent integration (`agent-integration/`)

| Doc | Topic |
|---|---|
| [agent-integration/README.md](agent-integration/README.md) | Index for agent developers. |
| [agent-integration/wire-contract.md](agent-integration/wire-contract.md) | What an agent sees: endpoints, headers, error codes, streaming. |
| [agent-integration/http-services.md](agent-integration/http-services.md) | Construct HTTP calls from typed discovery with only the agent's Locksmith token. |
| [agent-integration/native-mcp.md](agent-integration/native-mcp.md) | Stateful MCP 2025-11-25 lifecycle, wire errors and a pinned Python client. |
| [agent-integration/compact-mcp.md](agent-integration/compact-mcp.md) | The compact native MCP path, when an operator enables it. |
| [agent-integration/skill-reference.md](agent-integration/skill-reference.md) | The `/skill` endpoint: generic and personalized forms, cache headers. |
| [agent-integration/hermes.md](agent-integration/hermes.md) | Hermes: provider-config block and `*_BASE_URL` paths, multiple agents, OAuth providers. |
| [agent-integration/openclaw.md](agent-integration/openclaw.md) | OpenClaw via `*_BASE_URL`. |
| [agent-integration/examples/curl.md](agent-integration/examples/curl.md) | curl recipes for common operations. |
| [agent-integration/examples/python.md](agent-integration/examples/python.md) | Python: anthropic and openai SDKs, httpx, aiohttp, error handling. |
| [agent-integration/examples/typescript.md](agent-integration/examples/typescript.md) | TypeScript and Node: anthropic and openai SDKs, fetch, axios, streaming. |

## Change notes (`changes/`)

Read these before upgrading an existing installation.

| Doc | Topic |
|---|---|
| [changes/explicit-account-bindings.md](changes/explicit-account-bindings.md) | Explicit account bindings (3.0.0): compatibility and limits. |
| [changes/explicit-http-grants.md](changes/explicit-http-grants.md) | Explicit HTTP grants and activation (3.0.0). |
| [changes/connector-onboarding.md](changes/connector-onboarding.md) | HTTP connector onboarding (3.0.0): discovery, compatibility, upgrade and verification limits. |
| [changes/integration-definitions.md](changes/integration-definitions.md) | Integration definition activation and upgrade. |
| [changes/native-mcp.md](changes/native-mcp.md) | Native MCP lifecycle and migration. |

The [reviewed migration](concepts/migrating-account-bindings.md) covers backup,
preview, apply and restart. The
[local cutover smoke](../development/explicit-account-bindings-smoke.md) runs a
disposable daemon and CLI through SM01–SM05.
