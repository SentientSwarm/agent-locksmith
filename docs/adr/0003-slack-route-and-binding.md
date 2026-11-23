# ADR-0003: Slack workspace is the route; identity and method policy are the binding

Status: Accepted (rollout incomplete)
Date: 2026-11-23

## Context

AGENT-338 separates the workspace being addressed from the Slack account acting
there. Herd agents must act as John; app agents retain their own identities.
John approved full participation in his channels, private channels, DMs and
threads on 2026-11-22, with no agent label on posts. That permits reading private
content and posting as him; per-VM revocation, binding policy and audit are the
chosen controls. This is an accepted rollout decision, not evidence of cutover.

F-001 and F-002 implement the policy and workspace primitives; ADR-0001 and
ADR-0002 record their implementation. The remaining routing and runtime changes
are pending. The [scoped architecture](../concepts/slack-architecture.md) pins
what exists and distinguishes it from the target deployment.

## Decision

Use one HTTP Web API route per workspace, named `slack-<workspace>`, upstream
`https://slack.com/api`, declaring the expected `metadata.slack_team_id` with
`--slack-team-id`. Check sealed bearer ingestion and replacement using
`auth.test` before storing a value, as in ADR-0002
(`src/registrations/slack_workspace.rs:73`). A new workspace adds a route.

Select posting identity through each agent's explicit binding. Herd VM identities
select `--broker` to use John's user token sealed once on the route. App identities
select their own sealed bot bearer. Keep allow/deny method policy with each
binding, independently of credential replacement, as in ADR-0001
(`migrations/0028_binding_method_policy.sql:2`). Allow participant methods and
explicitly deny `admin.*`, `team.*`, `apps.*` and `users.profile.set` for herd
bindings; deny wins over allow (`src/method_policy.rs:29`). The policy restricts
Slack methods, not channels or message content; Slack scopes and membership still
bound the selected account's reach. Missing policy retains unrestricted methods.

**Implementation gap:** these two identity modes cannot yet share the proposed
route. Current broker admission requires a broker selection and always sends the
route key (`src/proxy/admission.rs:96`); ordinary routes materialize per-agent
stored bearers (`src/proxy/selection.rs:60`). Resolve this contract before live
shared-route/app onboarding. This ADR does not silently change that behavior or
claim F-003/F-004 and app cutovers have passed.

Keep Socket Mode for app agents. Send `apps.connections.open` through a separate
`slack-socket` HTTP route holding that agent's app-level token, then connect the
returned WebSocket directly to Slack. The existing site matrix already exercises
the HTTP method (`edge/evo-x2-1/locksmith/route_matrix.py:59` in layer8-proxy-site).
Locksmith does not proxy the WebSocket in this design. Its URL is a transient
capability and must not be logged. The participant Web API policy's `apps.*` deny
does not grant or configure the separate socket route.

Download private files through a separate `https://files.slack.com` route with
the app's sealed bot credential. Preserve the approved host and path when mapping
`url_private` downloads; never send a Locksmith agent bearer directly to Slack
or forward a file token to an arbitrary URL. This requires adapter work in F-011.
The current Hermes adapter still downloads with its bot token and validates CDN
URLs (`plugins/platforms/slack/adapter.py:6384` in hermes-agent@0f602c5f6f).
The Slack method policy only accepts literal method segments, so it must not be
reused on file URL paths (`src/method_policy.rs:29`).

Keep native MCP OAuth separate from Web API custody. The existing
`slack-confidential-v1` profile intentionally bundles expected workspace and user:
`auth.test` must match both and omit `bot_id`
(`src/oauth/consent/slack_identity.rs:19`). This is an assertion about one OAuth
account, not the posting route's identity model. Its two fixed scopes,
`search:read.public` and `channels:history`, do not satisfy the required full
participant reach (`src/oauth/consent/slack.rs:8`). F-008 will try a declared
custom contract and record Slack's acceptance or refusal; the herd Web API skill
is the fallback. No live MCP eligibility is asserted here.

## Consequences

Workspace, credential custody and authorization have distinct owners. Adding a
workspace should add a route and bindings, rather than redefine identity. Live
policy and sealed-key changes use existing admin interfaces without restarting
the daemon; configuration/profile edits remain startup-loaded. Secrets enter
through stdin or authenticated request bodies and remain absent from evidence.

Socket Mode traffic and transient capabilities bypass Locksmith after connection
setup; frame traffic therefore has no Locksmith request audit. Files and socket
setup need separate grants and credentials. Sealing custody alone does not prove
an agent holds no Slack token: runtime changes and attended cutovers must verify
that. Staging remains the pilot; this decision does not authorize production
cutovers or prove zone reachability.

## Alternatives considered

A route per posting identity conflates workspace and account and duplicates
workspace configuration. A route-wide method policy cannot distinguish John's
participant methods from bot methods. Sharing raw Slack tokens with runtimes
retains the custody problem. Tunneling WebSockets would require a new proxy
contract beyond this rollout. Treating the MCP profile as workspace-only would
remove its account identity check; keeping the explicit workspace/user assertion
preserves that OAuth boundary.
