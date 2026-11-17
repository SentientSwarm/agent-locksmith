# Operator how-tos

Task pages for running Locksmith. If you are new, work through the
[guide journeys](../guide/README.md) first; these pages go deeper on one
subject each. The [documentation entry point](../README.md) lists the
concept, reference and change-note pages.


## HTTP connections and accounts

| Doc | Topic |
|---|---|
| [connector-onboarding.md](connector-onboarding.md) | Validate a reference or customer HTTP service, grant a named agent, select its account and verify the receiving effect. |
| [account-binding-troubleshooting.md](account-binding-troubleshooting.md) | Error classes for explicit account access and how to repair them. |

## Integration definitions

| Doc | Topic |
|---|---|
| [integration-definitions.md](integration-definitions.md) | Immutable definitions, disabled exact pins and deliberate local customer activation. |
| [customer-mcp-journey.md](customer-mcp-journey.md) | From a customer definition to one deliberately granted MCP task for an agent. |

## Native MCP

| Doc | Topic |
|---|---|
| [native-mcp.md](native-mcp.md) | Native MCP lifecycle setup, current identity and upgrade requirements. |
| [native-tool-review.md](native-tool-review.md) | Observe, inspect and review native tools for an agent's account. |
| [native-tool-grants.md](native-tool-grants.md) | Grant or revoke finite reviewed native tools. |
| [native-contract-policy.md](native-contract-policy.md) | Choosing `finite-v1` or `finite-v2` contract policy. |
| [native-context.md](native-context.md) | Fixed native context and safe diagnosis. |
| [native-oauth.md](native-oauth.md) | Controlled OAuth accounts for native MCP. |
| [hosted-linear.md](hosted-linear.md) | The fixed hosted Linear OAuth profile and its offline twin. |

## OAuth

| Doc | Topic |
|---|---|
| [custom-oauth.md](custom-oauth.md) | Declared `custom-oauth-v1` contracts for preregistered services. |
| [custom-oauth-workflow.md](custom-oauth-workflow.md) | Activate and use a declared OAuth service. |
| [custom-oauth-profile.example.json](custom-oauth-profile.example.json) | Example declared profile (invented values). |
| [oauth-account-response-v1.schema.json](oauth-account-response-v1.schema.json) | JSON schema for OAuth account responses. |
| [oauth-consent.md](oauth-consent.md) | Controlled operator consent, owner-bound sealed custody and disconnect. |
| [oauth-recovery.md](oauth-recovery.md) | Uncertain refreshes, recovery and the 0013 upgrade. |
| [oauth-capability-proof.md](oauth-capability-proof.md) | Bounded OAuth refusal and lifecycle evidence. |

## Slack

| Doc | Topic |
|---|---|
| [slack-oauth.md](slack-oauth.md) | Confidential Slack OAuth accounts: profile, activation, consent and grants. |
| [slack-oauth-lifecycle.md](slack-oauth-lifecycle.md) | Renewal, retirement and upgrades. |
| [slack-callback.md](slack-callback.md) | Callback redirect setup and upgrade. |
| [slack-identity-diagnostics.md](slack-identity-diagnostics.md) | Identity response and safe diagnostics. |
| [slack-token-diagnostics.md](slack-token-diagnostics.md) | Token metadata diagnostics. |

## Custody and recovery

| Doc | Topic |
|---|---|
| [sealed-state-recovery.md](sealed-state-recovery.md) | Consistent snapshots, independent key recovery and quarantined restore. |
| [1password-setup.md](1password-setup.md) | Optional pattern (scripts not shipped): render deployment `.env` files from 1Password Environments. |

## Edge packaging

| Doc | Topic |
|---|---|
| [edge-packaging.md](edge-packaging.md) | Hardened systemd units in Incus containers, from a private site file. |

## Runbooks (`runbooks/`)

Each runbook was written when its feature shipped in 2.x and still
describes how that feature works. Ignore their notes about merging to
`develop` and upgrading from earlier milestones.

| Doc | Topic |
|---|---|
| [runbooks/remote-management.md](runbooks/remote-management.md) | The admin HTTPS listener, its certificates, and the CLI over HTTPS. |
| [runbooks/sealed-secrets.md](runbooks/sealed-secrets.md) | Sealed config secrets with systemd-creds and the hardened unit. |
| [runbooks/mtls-onboarding.md](runbooks/mtls-onboarding.md) | A new mTLS fleet: CA, agent and operator certificates, the bootstrap listener. |
| [runbooks/mtls-migration.md](runbooks/mtls-migration.md) | Moving a bearer fleet to mTLS without downtime. |
| [runbooks/mtls-revocation.md](runbooks/mtls-revocation.md) | Revoking a certificate: emergency blocklist and CRL refresh. |
| [runbooks/response-controls.md](runbooks/response-controls.md) | Response size caps, content-type allowlists and redaction. |
| [runbooks/proxy-bearer-acl.md](runbooks/proxy-bearer-acl.md) | Per-agent bearer tokens and tool ACLs on the proxy path. |
| [runbooks/inference-hardening.md](runbooks/inference-hardening.md) | Health endpoints (`/livez`, `/readyz`, `/version`) and the shutdown drain. |
