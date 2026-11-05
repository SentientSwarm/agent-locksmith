# Controlled operator consent

The optional `controlled-linear-v1` profile lets an authenticated operator create
and disconnect sealed, durable custody through the shipping CLI and daemon. It
supports a **local HTTPS twin only**. `connected_unbound` means that twin returned
the configured workspace and user IDs. It does not establish hosted Linear or
Slack support, a usable read grant, native OAuth activation, or agent access.
No registration, grant, selection, review or enabled flag changes as a side effect.

## Configure the controlled profile

Keep the OAuth sealing key in its existing secure environment source. It is
independent of `LOCKSMITH_CREDENTIAL_SEALING_KEY`. Consent requires the admin
substrate and a valid `LOCKSMITH_OAUTH_SEALING_KEY` at startup. Without the optional
section, existing configuration behavior is unchanged.

This invented example uses a TLS twin on port 19443 and a callback listener on
port 19444. Supply certificates whose SAN includes the literal loopback address,
and public CA files that validate them. The callback key stays private.

```yaml
oauth_consent:
  callback:
    address: 127.0.0.1:19444
    cert_path: ./callback.pem
    key_path: ./callback.key
  profiles:
    - id: twin
      kind: controlled-linear-v1
      client_id: fixture-client
      client_generation: 1
      issuer: https://127.0.0.1:19443
      authorization_endpoint: https://127.0.0.1:19443/authorize
      token_endpoint: https://127.0.0.1:19443/token
      resource: https://127.0.0.1:19443/mcp/readonly
      redirect_profile_id: local
      redirect_uri: https://127.0.0.1:19444/oauth/callback
      expected_workspace: 00000000-0000-0000-0000-000000000041
      expected_user: 00000000-0000-0000-0000-000000000042
      ca_path: ./provider-ca.pem
```

Only HTTPS literal `127.0.0.1` or `[::1]` addresses are supported, with nonzero
ports. Callback URI must exactly match the bound address and `/oauth/callback`.
Authorization and token origins equal the configured issuer. No discovery,
registration, proxy, redirect following, remote fallback or request retry occurs.
CA files add trust; verification stays enabled. Profiles are startup-only;
restart to change them. At most 8 distinct profiles are supported.

Create an ordinary manual HTTP tool registration through the existing operator
PUT `/admin/operator/tools/twin` interface, using this body (TLS/admin credentials
are supplied through your existing operator client):

```json
{"description":"Controlled identity twin","upstream":"https://127.0.0.1:19443/mcp/readonly","egress":"direct","auth":{"kind":"oauth_pkce","client_id":"fixture-client","redirect_uri":"https://127.0.0.1:19444/oauth/callback","scopes":["read"],"auth_url":"https://127.0.0.1:19443/authorize","token_url":"https://127.0.0.1:19443/token"}}
```

The profile must exactly match that registration. Definitions and native MCP
registrations are unsupported. The registration may remain disabled. Labels,
profile IDs and CLI path components are 1–128 ASCII letters, digits, `_` or `-`.

## Connect, inspect, disconnect

Use the existing operator token and UDS or configured admin HTTPS transport.
Operator ownership uses authenticated `public_id`, including mTLS, rather than
display name. Distinct principals may share a display name. Empty/duplicate
public IDs and duplicate certificate identities are rejected at startup.

```sh
locksmith --format json oauth account-status twin --label reader
# Read config_revision from this response; supply that integer below.
locksmith --format json oauth connect twin --label reader --profile twin \
  --client-generation 1 --redirect-profile local --expected-config-revision 1
```

Connect returns 201 with `attempt_id`, `state: pending`, Unix-second `deadline`,
`session_label`, and `authorization_url`. Only that response contains the URL.
Keep it private and open it manually in the controlled test browser. No browser
is launched by the CLI. Authorization uses S256, `scope=read`, the exact resource
and redirect URI. The callback requires `state`, `iss` matching the configured
issuer, and exactly one of `code` or `error`. Replayed, malformed or duplicate
parameters refuse; an unrelated invalid callback does not consume the attempt.

```sh
locksmith --format json oauth attempt-status twin ATTEMPT_ID
locksmith --format json oauth cancel twin ATTEMPT_ID
locksmith --format json oauth account-status twin --label reader
# Copy the opaque revision from account-status; it is not config_revision.
locksmith --format json oauth disconnect twin --label reader --if-match REVISION
```

Poll returns pending/exchanging/connected/failed/expired/canceled, deadline,
label, nullable account generation and a static `safe_reason`, `stage`, `cleanup`
and `finalization`. It never returns the URL, state, code, verifier or tokens.
A code is claimed once before exchange. Timeout or lost delivery is not permission
to replay it; poll and account-status reconcile the durable outcome.

Account status returns `connected_unbound`, kind `controlled_linear_v1`, profile,
account generation, opaque revision, current `config_revision`, nullable
`token_expires_at`, `requested_scopes: [read]`, nullable `granted_scope`, and
`identity_verified: true`. The identity statement refers only to the twin.
An omitted scope echo remains null. Omitted refresh and expiry remain absent;
no empty refresh token or invented lifetime is stored. Present expiry must be
positive and no greater than 365 days. Status does not unseal tokens.
If its registration was deleted, the existing account remains owner-readable
with `config_revision: null` and can still be disconnected. Deleting or recreating
the registration changes the revision: fetch current status before cleanup.
An absent account with no registration returns 404.

An absent account returns `state: absent`, null generation, config revision and
an opaque revision covering the current connection and active attempt. Another
owner's active attempt returns 404. Starting an attempt changes the absent
revision. Disconnect requires If-Match (missing 428, stale 409), cancels matching
pending work, and returns `disconnected` with retired generation or null and
`remote_revocation: unsupported`. It never contacts a revocation endpoint.

Cancel is idempotent for the owning attempt. If account commit won first, cancel
leaves that account connected. A new connect conflicts with an existing account
or active attempt; explicitly disconnect/revoke first. Committed accounts survive
attempt expiry, eviction and restart. Completed graceful-shutdown cleanup marks
unfinished attempts `failed` with `safe_reason: daemon_stopped`. At startup, any
remaining `pending` or `exchanging` attempts become `expired` with
`safe_reason: daemon_restarted`, including work left by an abrupt stop. Neither
path resumes provider work. No provider refresh is implemented for this kind.

## Identity and isolation boundaries

After token exchange, the daemon seals quarantine and initializes MCP 2025-11-25,
then lists tools and calls only `get_workspace({})` and `get_user({"query":"me"})`.
Both identity input schemas must admit those exact arguments before either call.
They use the [finite schema grammar](native-tool-review.md), including required
fields, string length, `const` and `enum`, with at most 128 nodes and depth 8.
For these fixed calls, root `additionalProperties` may be omitted or boolean;
schema-valued additional properties, references, compositions, patterns and other
unsupported keywords refuse. Nested object schemas still require explicit
`additionalProperties: false`. This bounded profile does not accept every valid
provider JSON Schema.

Both IDs must match. Project and issue schemas are unnecessary and those tools
are never called. Responses must contain exactly one text JSON object; structured
content, nested duplicate members, wrong response IDs, tool errors and known-token
strings or keys refuse. Only a verified identity permits atomic account commit.

Legacy `oauth list` hides controlled rows. Legacy status/revoke/bootstrap refuse
those rows with `oauth_kind_unsupported`; use the new owner-bound commands.
Legacy proxy and every refresh path refuse this kind before token use, including
when an agent previously selected the absent label. Native OAuth and definition
activation remain unsupported. Identity calls are internal verification traffic,
not useful agent dispatch. Existing legacy accounts retain their interfaces.

A failure uses static reasons, not provider text. Transport failures whose details
are hidden by the adapter remain `request_failed`. The primary stage survives
cleanup/finalization handling; cleanup may be `not_required`,
`attempted_helper_accepted`, `attempt_failed` or `incomplete`. Adapter acceptance
of DELETE 405 does not prove remote session deletion. A committed account is not
rolled back because a later diagnostic write fails. Reconcile unknown COMMIT
outcomes through status; do not assume rollback.

## Bounds and upgrade

Attempts last 600 seconds, including exchange and commit. There are 8 active
attempts per operator, 32 total, 128 retained attempt records, 128 controlled
accounts, 16 concurrent operations and 32 callback TLS connections. Each provider
request is bounded to 5 seconds, the complete operation to 40 seconds, cleanup to 6.
The callback URI is at most 8 KiB with 16 parameters. Identity inventory is one page
and at most 256 tools; raw MCP bodies are 512 KiB, JSON work 32768 units, SSE 128 events.
Terminal secrets are erased immediately; terminal records expire after 24 hours or
are evicted oldest-first for capacity. Reducing a page size cannot make unsupported
schema/result shapes valid.

Take the [consistent sealed-state backup](sealed-state-recovery.md) before
upgrade. Migration 0015 preserves legacy sealed bytes, refresh markers, versions
and the historical incarnation sequence, including deleted rows. It adds nullable
refresh custody only for the new kind. Older binaries reject the migrated database
or new configuration before serving; downgrade requires a complete older snapshot
and matching keys, with the refresh-replay precautions in
[OAuth recovery](oauth-recovery.md). Do not launch an older binary against live
upgraded state. No installed, remote, power-loss or full provider acceptance is
implied by controlled tests.
