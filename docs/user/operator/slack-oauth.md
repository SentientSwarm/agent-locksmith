# Confidential Slack OAuth accounts

The shipping daemon supports the explicit `slack-confidential-v1` user profile
through existing owner-bound consent, sealed accounts and finite native grants.
The separate `slack-confidential-fixture-v1` kind supports invented local receiving.
Offline tests do not establish actual app eligibility, installed scopes, provider
S256 enforcement or live MCP schema compatibility. No app registration, installation,
credential discovery or browser automation occurs.

For an explicitly declared root/nested user-token variant, see
[declared OAuth contracts](custom-oauth.md). Switching contracts changes the digest
and requires the documented confidential generation/reconnect workflow. The named
profiles below retain the original strict nested-user contract.

## Configure the profile

Use an already configured confidential client, exact trusted workspace/user IDs,
and the two intended user scopes `search:read.public` and `channels:history`.
The following identifiers are invented. Both existing sealing keys are needed for
new confidential consent: `LOCKSMITH_CREDENTIAL_SEALING_KEY` protects the client
secret; `LOCKSMITH_OAUTH_SEALING_KEY` independently protects tokens. Keep keys in
their existing secure environment source, never YAML or arguments.

```yaml
oauth_consent:
  callback:
    address: 127.0.0.1:19444
    cert_path: ./callback.pem
    key_path: ./callback.key
  profiles:
    - id: slack-reader
      kind: slack-confidential-v1
      client_id: REPLACE_WITH_REGISTERED_CLIENT_ID
      client_generation: 1
      issuer: https://mcp.slack.com
      authorization_endpoint: https://slack.com/oauth/v2_user/authorize
      token_endpoint: https://slack.com/api/oauth.v2.user.access
      resource: https://mcp.slack.com
      redirect_profile_id: callback
      redirect_uri: https://callback.example.test/oauth/callback/slack
      expected_workspace: TTEST001
      expected_user: UTEST001
      ca_path: ./provider-ca.pem
```

The OAuth resource is exactly `https://mcp.slack.com`; it is carried in the
authorization, code-exchange and refresh requests. The MCP transport endpoint is
separately fixed at `https://mcp.slack.com/mcp`, used for native POST and session
DELETE. The daemon derives this mapping from the explicit profile kind; there is
no arbitrary endpoint override, redirect or token-driven audience inference.
These real-kind endpoints are fixed. The callback authority may differ from the
literal-loopback local TLS bind; supply matching routing/certificates independently.
Use the dedicated path `/oauth/callback/slack`, with no query, fragment or user
information. Only this state-bound Slack route permits an absent response `iss`.
A supplied issuer must still match exactly. Legacy `/oauth/callback` retains
mandatory issuer checking; see [callback setup and upgrade](slack-callback.md).
Forwarded headers do not substitute for the configured Host. The CA file adds
trusted roots to normal TLS verification. Profiles and native CA identity are
loaded at startup. Client ID/generation, exact endpoints, identities, redirect and
loaded native roots contribute to current authority.

For an offline twin, use the separately named fixture kind with issuer
`https://127.0.0.1:19443`, resource `https://127.0.0.1:19443`, MCP endpoint
`https://127.0.0.1:19443/mcp`, authorization `/oauth/v2_user/authorize`,
token `/api/oauth.v2.user.access`, and identity `/api/auth.test` on that same origin.
Use a trusted local test CA. The fixture kind also retains its historical resource
`https://127.0.0.1:19443/mcp`; both explicit fixture forms use `/mcp` transport.
Historical fixture URLs retain their parsed same-origin validation and exact
transport spelling, including an explicit default port.
That compatibility case does not apply to the real kind or redirect its credentials.

## Create and activate a customer connection

Start with [the invented definition](../../../definitions/customer-slack.example.json)
and [definition authoring](integration-definitions.md). Definition text is descriptive;
it does not authorize a provider or token. Replace its workflow names only after
learning the actual supported contract. An invented fixture uses `search_messages`
and `read_thread`; these names are not a claim about the live provider.

```sh
locksmith integration import --file definitions/customer-slack.example.json
locksmith tool from-definition slack --definition local.customer-slack --revision 1 \
  --auth-profile confidential --upstream https://mcp.slack.com/mcp
locksmith --format json tool get slack
# Use the returned definition_control.revision.
locksmith tool activate-definition slack --if-match DEFINITION_REVISION \
  --oauth-profile slack-reader --contract-policy finite-v2 --compact \
  --selected-tool search_messages --selected-tool read_thread
```

A local twin also needs `--allow-private-destination` at creation. Activation
checks exact declared scopes, derived MCP endpoint and profile digest; it performs no provider I/O.
Selection scans the complete bounded catalog (256 tools/four pages), retains at
most 32 exact selected schemas within 48 KiB and reports omissions. Unsupported
selected contracts refuse; provider metadata never grants authority. See
[finite contracts](native-contract-policy.md) for unchanged invocation limits.

## Seal the client and complete owned consent

Provision from a protected local file or pipe; plaintext has no CLI argument or
config field. The CLI accepts one nonempty printable ASCII value of at most 8192
bytes and removes one trailing newline. Use normal authenticated operator access.

```sh
locksmith oauth client set slack --profile slack-reader --client-generation 1 \
  --secret-stdin < protected-client-secret
locksmith oauth client status slack --profile slack-reader --client-generation 1
locksmith --format json oauth account-status slack --label account-x
# Use the returned config_revision.
locksmith oauth connect slack --label account-x --profile slack-reader \
  --client-generation 1 --redirect-profile callback \
  --expected-config-revision CONFIG_REVISION \
  --scopes search:read.public,channels:history
locksmith oauth attempt-status slack ATTEMPT_ID
locksmith --format json oauth account-status slack --label account-x
```

Open the one-time private authorization URL manually. Consent uses S256 and
`client_secret_post`; the client secret is sent only in the token request body.
An attempt lasts at most 600 seconds. The supported token response requires root
`ok:true`, `access_token` and `token_type:"user"`, with exact nested
`authed_user.id/scope` and `team.id`. For the invented IDs above, a complete
accepted token body is:

```json
{
  "ok": true,
  "access_token": "invented-access-token",
  "token_type": "user",
  "refresh_token": "invented-refresh-token",
  "expires_in": 3600,
  "authed_user": {
    "id": "UTEST001",
    "scope": "search:read.public,channels:history"
  },
  "team": {"id": "TTEST001"}
}
```

Token fields belong at the root; a nested-only token response refuses. Access
and non-null refresh tokens must be nonempty printable ASCII without spaces,
at most 8192 bytes. Initial root `refresh_token` and `expires_in` may be absent
or null. A non-null expiry must be an integer from 1 through 31536000 seconds.
If `authed_user` also contains `access_token`, `token_type`, `refresh_token` or
`expires_in`, each must exactly equal its root field; a nested field without its
root counterpart refuses, and null differs from absence. Duplicate JSON object
keys refuse. Optional root `scope`, `team_id`, `user_id`, `issuer`, `iss`,
`resource` and `client_id`, when present, must agree with the configured profile
and required metadata. Scopes contain exactly the two declared entries, in
either order. Bot tokens and HTTP 200 `ok:false` refuse.
A separate bearer-authenticated fixed `auth.test` request must confirm both IDs
before quarantined tokens become an account. No identity is inferred from a token.
Its complete minimal accepted body for this fixture is:

```json
{"ok": true, "team_id": "TTEST001", "user_id": "UTEST001"}
```

Both responses require HTTP 200. Identity responses must omit `bot_id` and
`error`; token responses must omit `bot_user_id` and `error`. These examples
document the supported twin contract, not a claim about a live provider response.

Status reveals metadata only. `connected_unbound` is custody, not current token
usability or agent authority. Missing/null initial expiry remains unknown;
missing/null refresh means refresh unavailable. Malformed non-null values refuse.
Native use materializes access only and does not require an optional refresh token.

Grant the agent connection ACL, select the current owned account using
`locksmith agent select-oauth AGENT slack --label account-x --if-match REVISION`,
then [observe, explicitly review and grant](native-tool-review.md) the exact tools.
Include `contract_policy: finite-v2` in each review. Both standard and compact
facades require the same current account, schemas, arguments and committed grants.
The declaration, activation, consent and selection each grant no tools by themselves.

## Renewal, retirement and upgrade

See [Slack OAuth lifecycle and upgrades](slack-oauth-lifecycle.md) for refresh
repair, permanent client retirement, pre-upgrade resource changes, schema
compatibility and bounded diagnostics. Retire existing old-profile client
generations with the supported old binary and configuration before changing the
resource or upgrading.
