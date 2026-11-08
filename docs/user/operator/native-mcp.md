# Native MCP lifecycle setup

For owner-selected controlled OAuth, see [native OAuth accounts](native-oauth.md).

Locksmith supports authenticated MCP **2025-11-25 stateful Streamable HTTP** at
`/mcp/{connection}`. Connection access and explicit account selection permit the
session lifecycle; they do not approve tools. [Review and grant](native-tool-review.md)
adds finite useful calls for manual None/live sealed-bearer and deliberately
selected controlled OAuth accounts. Offline
[definitions](integration-definitions.md) remain disabled exact revision pins.
Use [HTTP onboarding](connector-onboarding.md) for existing HTTP services.
Provider consent and verified external identity are separate; configuration
status does not attest provider or per-account credential readiness.

## Before setup

Build both binaries with `cargo build --locked --bins`. Use the
[getting started guide](../getting-started.md) for operator bootstrap, a private
admin socket, database and daemon setup. Native access requires that database
and an actual registered agent identity. A shared gateway bearer or identityless
legacy setup cannot create a native session.

Use the existing agent listener's verified TLS configuration (`auth_mode: mtls`
or `both` and `listen.mtls` CA/server certificate/key paths). `both` accepts a
registered per-agent bearer over TLS or a client certificate bound with
`locksmith agent set-cert-identity AGENT_ID CERT_IDENTITY`. Operator and agent
credentials are distinct. Give consumers the daemon URL and CA trust separately;
never use disabled certificate verification. Plain bearer listeners remain
available for local deployments, with the same native identity requirements.

The optional top-level `mcp` configuration is restart-only:

```yaml
mcp:
  allowed_hosts: ["locksmith.example:9200"]
  allowed_origins: []
```

Use the actual listener authority in `allowed_hosts`; defaults are localhost,
127.0.0.1 and [::1], permitting their listener ports. A specified Host port must
match. Origin absence is allowed. If a browser sends Origin, configure its exact
HTTP(S) origin; an empty list rejects every present Origin. Scheme and port matter;
there are no wildcards or portless Origin exceptions. These rules affect `/mcp/`
only, preserving HTTP service behavior.

## Configure a connection and a named agent

Store this non-secret object in `mcp.json`:

```json
{"protocol_version":"2025-11-25"}
```

For compact search/full describe/invoke, use this explicit opt-in **before** setup:

```json
{"protocol_version":"2025-11-25","compact":true}
```

The standard route stays available; authenticated discovery adds `compact_path`.
Omitted/false keeps prior serialized metadata. Changing this configuration clears
connection/bootstrap authority, selections, observations, reviews and tool grants;
restore them deliberately. Pre-compact daemons fail startup with a stored
true field, affecting all listener availability. See [compact limits and upgrade
costs](../agent-integration/compact-mcp.md); no automatic downgrade is supported.

Then use the normal operator credential and admin socket configuration:

```sh
locksmith tool put sample --upstream https://service.example/mcp \
  --auth none --egress direct --protocol mcp_streamable_http \
  --mcp-config-file mcp.json
locksmith agent register --name native-consumer --allowlist sample
locksmith agent set-credential AGENT_ID sample --no-auth
locksmith tool get sample
```

Replace `AGENT_ID` with the returned public ID. Deliver the one-time agent token
through your normal private channel. Here `none` deliberately selects no account
credential; it does not bypass review. Live sealed-bearer references can be
selected with the existing account commands and used for observation and
reviewed dispatch; follow [the account and grant workflow](native-tool-review.md).
Selection alone does not verify provider identity or readiness. Do not put
provider values in metadata or this file.

The operator PUT/seed shape adds `protocol: mcp_streamable_http` and
`mcp: {protocol_version: "2025-11-25"}` to a `kind: tool` registration.
Missing protocol defaults to `http`; HTTP forbids `mcp`. Native model/infra,
unsupported versions/fields, HTTP service descriptions on a native registration,
proxied egress, and non-HTTPS endpoints are rejected before persistence. URL userinfo, queries,
fragments, backslashes and control characters are forbidden. Normal base paths
are valid. Obvious private/loopback destinations require explicit
`"allow_private_destination": true` in `mcp.json`; the known local listener
endpoint is always rejected. Operator observation separately enforces connected-address, DNS and trust policy;
authoring here does not establish outbound reachability.

PUT is a full replacement. Always send the native protocol and config when
updating a native connection. Changing protocol/config/destination/egress or
deleting/recreating it removes its connection grants and account selections
atomically, including bootstrap scopes. Approve those choices again deliberately.
Metadata-only changes preserve choices but retire old native sessions after
activation; native registration revisions prevent immediate lifecycle ABA.
Disable/re-enable preserves choices but invalidates existing sessions. Any agent
policy or account selection mutation can conservatively retire that agent's
native sessions. Sealed-bearer token rotation alone does not. Controlled OAuth
refresh changes the token version and retires old authority/scopes: reobserve,
review, regrant and open a fresh session as described in [native OAuth](native-oauth.md).

## Verify and diagnose

Use [the agent interface](../agent-integration/native-mcp.md) with the agent token.
`GET /tools` should show `type: mcp`, `/mcp/sample`, protocol version and
`tool_authority: reviewed_per_agent`; it must not advertise `/api/sample`. `account_selected`
and `activation: active` do not prove credential readiness (`not_checked`).

Initialize and ping should succeed. A connection with no reviewed tools lists
empty and refuses calls. Follow [review and grant](native-tool-review.md) for
positive execution; opening a new session after a grant allows its first list
to pin the effective tools. `/api/sample/...` still refuses without forwarding.

401 means no current agent identity. 403 means missing connection grant/account
selection or rejected Origin/Host. 404 means unavailable connection/session;
503 includes pending activation, unavailable state and shutdown. Inspect the
operator registration, agent policy and explicit account selection; correct the
specific state and create a fresh session. Never retry an ambiguous tool call.
429 includes `Retry-After: 1`; close your session before requesting another.

Best-effort `native_lifecycle` and `native_tool_denied` audit events contain
operation, agent public ID and connection name. They do
not log arguments, request/session IDs, credentials or upstream auth data and
are not committed tool-admission receipts. Positive dispatch separately commits
`mcp_admitted` before submission; best-effort `mcp_outcome` links the outcome.
A missing outcome is unknown, never proof of no effect. See [upgrade notes](../changes/native-mcp.md)
and [finite limits](../../development/native-mcp.md).

SDK payload tracing is suppressed even when `RUST_LOG` enables `rmcp`.
Use the application-owned lifecycle/denial audit and resource diagnostics;
client metadata, request IDs/arguments and cancellation reasons are not logs.
