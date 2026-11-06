# Controlled OAuth accounts for native MCP

This local profile connects a controlled HTTPS twin. It does not establish hosted
Linear/Slack support or activate definition-derived registrations. Start with
[controlled consent](oauth-consent.md). Its strict workspace and user checks
verify the configured twin identities. `connected_unbound` describes sealed
account custody, not current token usability or agent authority.

Configure a manual `mcp_streamable_http` tool with direct HTTPS egress, the exact
controlled profile resource and OAuth PKCE template, and valid `mcp` configuration.
The profile resource remains `/mcp/readonly`; its configured authorization/token
endpoints, client generation, S256, redirect, read scope and expected identities
remain unchanged. Definitions stay disabled. Set `compact: true` before granting
connection access if the compact facade is wanted. Changing protocol, upstream,
egress or MCP configuration removes selections, connection allowlists/bootstrap
scope and finite authority; explicitly repair them afterward.

Grant the agent's connection ACL first. Complete consent as the operator who will
own the account. Neither consent nor a legacy `--oauth-session` selection grants
native authority. Then inspect the current owner-bound account revision and
select it deliberately:

```sh
locksmith oauth account-status records --label account-x
locksmith agent select-oauth AGENT records --label account-x --if-match REVISION
```

Replace `AGENT` and `REVISION` with the exact public ID and account revision from
the supported commands. Two agents can select the same owned account; another
operator cannot select, inspect or prepare it, even with the same display name.
Ownership uses the authenticated operator public ID for bearer and mTLS access.
An agent uses the stored delegation; its own public ID is not the operator owner.
Generic credential listing omits another operator's controlled selections.
Administrators may still remove access with the existing revoke/unset controls.

Selection requires an active agent, its connection ACL, an enabled manual native
registration, an owned account, matching incarnation/profile/identity and a usable
current token state. It performs no provider request and decrypts no tokens. It
returns `source`, the selection stamp, `requires_observation: true` and
`callable: false`. Follow [finite tool review](native-tool-review.md): show, observe,
review each exact contract, replace the finite grants, then open a new standard or
[compact](../agent-integration/compact-mcp.md) session and list tools. Both facades
use the same dispatcher and committed admission audit. An empty first list stays
pinned; granting tools later requires a fresh session.

The corresponding operator API is:

```text
PUT /admin/operator/agents/AGENT/oauth-selection/REGISTRATION
Content-Type: application/json
If-Match: ACCOUNT_REVISION

{"label":"account-x"}
```

The body is strict: only `label`. Missing If-Match is 428. A stale revision, or an account whose profile,
incarnation or identity no longer matches, is 409 `source_conflict`. An
absent/foreign account is 404, an unsupported or unusable selection 400, and an
unavailable store/key 503. `controlled_oauth` is a selection-only stamp containing
`session_label`, `owner_id`, `incarnation`, `profile_id` and `profile_digest`.
Generic credential writes, registration/import/seed paths cannot create it. It
contains neither tokens nor copied token endpoints. Ordinary native observation,
review and grant endpoints enforce ownership inside their current-source
transaction, including publication after observation. Raw token values are never
returned.

## Refresh, reconnect and token lifetime

Native materialization uses the OAuth sealing key and decrypts only the access
token. It does not copy it into the stored-bearer domain, decrypt an optional
refresh token, initiate refresh, retry a tool call, or fall back to another source.
Missing access expiry means unknown expiry and is permitted; a known expired token
is refused. Pending refresh, degraded custody, exhausted version, mismatched
profile or unreadable ciphertext also refuse. No safety claim covers an unheld
refresh value in native response screening.

Manual `oauth refresh` remains owner/revision-bound. Its pending claim immediately
invalidates native authority; successful refresh changes the token version again.
The existing same-incarnation selection can remain, but observation, reviewed
contracts, grants and old sessions no longer authorize calls. Explicitly observe,
review, regrant and open a fresh session. Disconnect removes controlled selections.
Fresh consent after disconnect creates a new incarnation and requires selection
again. Old labels, grants and handles never revive the new account automatically.

The account authority includes registration identity, the selection stamp, current
token version and the digest of the profile CA bytes loaded at daemon startup.
Native controlled clients use those frozen roots with standard trust, retaining
DNS pinning, no redirects, private-destination opt-in and self-listener refusal.
Replacing a CA file at the same path affects the next startup and invalidates old
authority; there is no live trust reload. The configured path is not authority.

Before TOOL submission, the dispatcher rechecks current account/grants and expiry
through the final admission transaction, after database waits and again after
COMMIT. A refresh or authority change before committed admission refuses the stale
call with zero TOOL effects; initialization traffic is counted separately. A
change after committed admission can race one already-admitted captured-token
call. This is not rollback of provider effects.

## Upgrade and evidence limits

Migration 0017 adds selection constraints and account-delete cleanup. It does not
rebuild OAuth accounts or alter sealed legacy bytes, optional fields or historical
incarnation highwater. A schema-16 binary refuses the upgraded schema at
whole-daemon startup, including HTTP availability. Reupgrade with the current
binary; an old binary needs a complete untouched prior snapshot under
[sealed-state recovery](sealed-state-recovery.md), not an in-place downgrade.

An inherited controlled account can match the current profile/registration under
the existing limited policy. This does not reconstruct its original registration
instance or prove hosted provider adoption. None/StoredBearer native selection
and legacy HTTP account behavior remain separate supported paths. Controlled
selections are ineligible for legacy HTTP and background refresh.
