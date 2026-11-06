# Declared OAuth contracts

Use `custom-oauth-v1` for a preregistered service whose wire contract matches one
of the finite adapters below. The same shipping binary handles independently
configured services and the declared Slack variant; no provider code change is
needed. An `oauth_pkce` registration alone does not establish a trusted contract.

Only authorization-code S256 is supported. A service-principal subject describes
who the authenticated identity endpoint verifies; it does not enable the
client-credentials grant. Discovery, dynamic registration, script transforms,
background refresh and response-supplied endpoints are unsupported.

## Declare the contract

The [user/workspace example](custom-oauth-profile.example.json) uses invented
origins, scopes and identities. Place the profile in `oauth_consent.profiles`;
configure the ordinary callback listener and TLS files as in
[owner-bound consent](oauth-consent.md). `ca_path` adds trust roots; it never
disables TLS verification. No client secret belongs in configuration.

All authorization, token, resource, MCP and identity endpoints must use one of
1–4 explicitly approved canonical HTTPS origins. Paths are exact; URL credentials,
query strings, fragments and redirects are refused. Resource and MCP endpoint
are distinct declarations. Identity uses an explicit GET or POST with the new
access token, a five-second deadline and a 65,536-byte response limit.

`contract` version 1 declares `authorization_code_s256`, `pre_registered`, and
client authentication `none` or `client_secret_post`. Unknown capabilities and
fields refuse configuration. Every contract field participates in the profile
digest, including subject policy, scopes, endpoint paths and callback mode.

The subject is exactly one of:

- `{"kind":"user_workspace","workspace_id":"tenant-example","user_id":"person-example"}`,
  with identity adapter `workspace-user-v1` or `slack-auth-test-v1`.
- `{"kind":"service_principal","subject_id":"service-example"}`,
  with identity adapter `service-principal-v1` and token adapter `oauth2-bearer-v1`.

These are expected values, not evidence. The identity endpoint must return the
actual subject; publication and refresh compare that observation before commit.
Service principals persist no fabricated workspace or user. Owner account status
adds `verified_subject` only for custom contracts. Its `requested_scopes` and
`granted_scope` come from durable accepted response evidence, even if the current
profile is later removed or replaced.

## Wire adapters

`oauth2-bearer-v1` requires root `access_token`, case-insensitive `Bearer`
`token_type`, and root `scope`. Access and optional refresh tokens are nonempty
printable ASCII up to 8,192 bytes. Optional `expires_in` is a positive integer
up to 31,536,000 seconds. Null or malformed optional credentials/lifetimes refuse.
OAuth error members always refuse. Present issuer, resource, client and subject
echoes must match exactly; they are never alternative credential locations.

`slack-user-v2` accepts two complete shapes. With `authed_user` present, it must
contain exact `id` and `scope`, `team.id` is required, `ok` is true, and the root
user token and nested credential echoes must agree. With `authed_user` absent,
root `scope`, `access_token`, and `token_type` (`user` or `Bearer`) are required.
Optional `team.id`, root team/user and issuer/resource/client echoes stay strict.
A present malformed or null nested parent never falls back to root. Root `ok`,
if present, must be true; error members and bot claims refuse. Initial null
refresh/expiry retains Slack optionality; explicit null refresh during refresh
refuses. No token shape establishes identity by itself.

Identity bodies are JSON objects. `workspace-user-v1` requires observed
`workspace_id` and `user_id`; `service-principal-v1` requires `subject_id`.
`slack-auth-test-v1` requires `ok:true`, exact `team_id` and `user_id`, with no bot claim.
Its optional `team` display label is a string, distinct from a token response
`team.id` object. Display labels never establish identity. See
[identity diagnostics](slack-identity-diagnostics.md).
Missing, null, conflicting or wrong identities, duplicate JSON fields, secret
echoes and oversized responses refuse. No configured expectation is copied into
an observed identity. Unknown response fields confer no authority.

Scopes are 1–32 unique ASCII tokens, each 1–128 bytes, without whitespace, comma,
quote or backslash. Request separators are `space` or `comma`; response separators
are `space`, `comma`, or `space_or_comma`. Only the latter accepts mixed separators.
ASCII spaces around separators normalize; controls, empty comma elements,
duplicates, missing or extra scopes refuse. Every exchange and refresh requires
exact response scope evidence. Missing scope never inherits the request or the
old token. Accepted scope is stored in declared order separated by spaces.

Complete invented token and identity examples:

```json
{"access_token":"invented-access","token_type":"Bearer","scope":"records:read catalog:inspect","refresh_token":"invented-refresh","expires_in":3600}
```

```json
{"workspace_id":"tenant-example","user_id":"person-example"}
```

For a service principal, the independent identity body is instead
`{"subject_id":"service-example"}`. For the Slack root variant, configure
`slack-user-v2` plus `slack-auth-test-v1`; the identity response is
`{"ok":true,"team_id":"TEXAMPLE","user_id":"UEXAMPLE"}`. Use actual trusted
expected IDs and the provider's intended exact scopes in the declaration.
The observed earlier Slack refusal established only absent `authed_user`; other
returned fields were not retained. Offline variant tests do not prove a live
response, app permission, S256 enforcement or catalog compatibility.

## Callback and lifecycle

`issuer_required` uses `/oauth/callback` and requires exact response `iss`.
`distinct_redirect` uses `/oauth/callback/custom/<redirect_profile_id>` and permits
absent `iss` only there. The received HTTPS authority and exact path must match
the state-bound profile before claim. Distinct routes cannot be shared across
issuers, including equivalent host-case/default-port spellings. A supplied wrong
issuer always refuses. Forwarded headers and encoded or absolute paths confer
no callback authority.

Follow the [activation and account workflow](custom-oauth-workflow.md). New
contract fields change the profile digest. For a confidential account, retire
using the supported old configuration before switching; then configure a fresh
client generation, reactivate the definition and reconnect. Existing named
Linear/Slack profiles retain their serialized digest and strict behavior.
Migration 0022 preserves account sequence highwater and existing ciphertexts;
old binaries refuse the new schema. Back up according to normal operator policy
before upgrading. Do not move proof grants or keys into this account store.
