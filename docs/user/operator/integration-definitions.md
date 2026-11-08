# Author and activate customer integrations

This offline authoring stage saves a strict, immutable definition and creates a
**disabled** native connection pinned to its exact revision and content digest.
Importing does not contact a provider, execute a workflow, obtain credentials,
select an account, grant access or approve tools. The pin is configuration,
not evidence that a provider works. Ordinary agent credentials cannot author it.

Full AGENT-203 remains pending accepted Linear (AGENT-195), Slack (AGENT-196)
and keyed Context7 (AGENT-200) contracts. Operator/live setup (AGENT-194) is also
unaccepted. Local customer activation can reuse the controlled consent, manual
refresh and native dispatch paths described below. It does not accept hosted
providers, full AGENT-203/208, G0/G1 or release readiness.

For the complete local operator-to-agent sequence, including useful task
discovery and deliberate refusal/repair, use the [customer MCP journey](customer-mcp-journey.md).
Bounded local promotion is supported; the provider limits above remain.

## Prepare and import

Use the existing [operator setup](../getting-started.md) and authenticated
admin UDS or HTTPS connection. Build both binaries with `cargo build --locked
--bins`, put `target/debug` on your PATH, and set `LOCKSMITH_SOCKET` and
`LOCKSMITH_OP_TOKEN` for your disposable daemon. HTTPS instead uses
`LOCKSMITH_ADMIN_URL` and `LOCKSMITH_CA_BUNDLE`. Never place credentials in a
definition, shell history or an evidence report.

From the repository root, the shipped [customer example](../../../definitions/customer.example.json)
is a complete supported input. Copy it to author your own `local.*` definition.
The destination is a separate instance input; importing a reference URL never
fetches it. These commands use the same authenticated backend:

```sh
locksmith integration import --file definitions/customer.example.json --format json
locksmith integration get local.customer --revision 1 --format json
locksmith tool from-definition customer --definition local.customer --revision 1 \
  --auth-profile none --upstream https://example.com/mcp --format json
locksmith tool get customer --format json
```

Expect the import/get response to contain `definition`, `digest`,
`authoring_only: true`, `verification_source: operator_declared` and
`provider_readiness: unverified`. The connection reports `configured: true`,
`disabled: true`, `activation: disabled`, `credential_readiness: not_checked`
and `mcp.definition` containing `id`, `revision`, `digest`, `auth_profile_id`.
`auth: {kind: none}` is an inert template, not an account selection.

Native destinations require HTTPS without userinfo, query or fragment, direct
egress, and a non-self endpoint. Ordinary path prefixes are allowed. Private
IP/localhost destinations require `--allow-private-destination`; that flag does
not activate the connection or disable TLS verification. No DNS/provider probe
runs during creation. HTTP and manually authored native connections retain
[their existing setup](native-mcp.md).

## Deliberate customer activation

Only a `local.*` pin can be promoted. The declared profile fixes the permitted
selection mechanism: `none` with empty scopes requires explicit None; `bearer`
with empty scopes requires a live stored bearer reference; `oauth_provider`
with exactly `["read"]` requires an explicitly configured controlled-linear-v1
profile. Header profiles, other scope combinations and all bundled `builtin.*`
profiles remain refused. Candidate/fixture labels never grant eligibility.

The [bearer example](../../../definitions/customer-bearer.example.json) and
[controlled example](../../../definitions/customer-controlled.example.json)
are complete authoring inputs. They contain no endpoint or credential. For the
controlled variant, first configure [controlled consent](oauth-consent.md),
create the instance with its exact profile resource, then use `--oauth-profile`
with that trusted profile's ID. The server obtains the profile digest and PKCE
template; a definition cannot supply them or change the trusted endpoints.

Read `definition_control.revision` from `tool get` and supply it literally:

```sh
locksmith tool get customer --format json
locksmith tool activate-definition customer --if-match REVISION --compact --format json
```

For the controlled variant append `--oauth-profile PROFILE_ID`. Omit that option
for None/bearer. Omit `--compact` for standard MCP only. HTTP clients use
`PUT /admin/operator/tools/NAME/definition-activation`, `If-Match: REVISION` and
`{"enabled":true,"compact":true}` (plus `"oauth_profile_id":"PROFILE_ID"`
only for controlled OAuth). No secrets belong in these commands.

Promotion preserves the exact pin and destination and performs **zero upstream
requests**, including no retry of unrelated degraded credential-backend references.
Its runtime reconciliation publishes the catalog only. It creates no account, agent selection, connection ACL, review or
tool grant. `definition_control.phase: promoted` reports saved configuration;
`activation: active` reports runtime catalog agreement. Neither means callable.
`credential_readiness` remains `not_checked`, `provider_readiness` remains
`unverified`, and the definition itself remains `authoring_only: true`.

Grant an agent's connection ACL deliberately, then select its account:

```sh
locksmith agent register --name customer-agent --allowlist customer
locksmith agent set-credential AGENT customer --no-auth
```

The second command is only for a None declaration. For bearer, use the existing
`--stored-bearer-stdin` ingestion or `--stored-bearer-ref REF` selection; do not
put a value in argv. Wrong mechanism or unavailable reference refuses without
changing the selection or creating a sealed row. For controlled OAuth complete
owner-bound consent, inspect `oauth account-status`, and use
[select-oauth](native-oauth.md) with its separate account revision. An old legacy
OAuth label or registration template cannot substitute for that selection.
Then follow [finite tool review](native-tool-review.md): show/observe, review each
exact contract, replace finite grants, and open a fresh standard or
[compact session](../agent-integration/compact-mcp.md). These are separate steps;
metadata-only discovery does not invoke tools.

## Disable and repair

```sh
locksmith tool get customer --format json
locksmith tool deactivate-definition customer --if-match REVISION --format json
```

The disable API body is exactly `{"enabled":false}`. Disable retains the pin,
destination, compact setting and sealed owned accounts, but removes all connection
ACL/bootstrap scopes, selections, observations, reviews and tool grants. It is
local revocation, not a remote provider revoke. It works even if the controlled
profile or key is unavailable. Reactivation requires deliberate ACL, selection,
observation, review, grant and fresh sessions. Changing an active compact setting
or controlled profile also requires disable then activate. Refresh/version/root
changes and reconnect retain the [controlled repair costs](native-oauth.md).

A current-revision retry with exactly the same desired state issues no database
UPDATE and only resynchronizes runtime; repaired authority survives. A stale
revision always returns 409, even after a lost response or delete/recreate. Read
fresh state before repair. Missing precondition returns 428; malformed/unsupported
input 400; absent/unpinned target 404. A 503 with `saved:true` and `activation:pending`
means persistence committed but runtime resync failed. A timed-out submitted
operation reports `saved:null`, `outcome:unknown`: do not assume rollback. Fresh
GET and exact-state retry (or restart) repair catalog agreement before dispatch.

## Revisions, refusals and removal

An import of identical typed content at the same ID/revision is a successful
no-op. Whitespace and object-key order are irrelevant; array order and every
value are significant. Different content at that key returns HTTP409 / CLI5.
Import a new positive integer revision instead. There is no `latest`, update,
list, delete-definition or batch import operation. A JSON array is rejected as
a whole before storage. Definitions are not imported automatically at startup.

Creating an instance is create-only: an existing connection name returns409,
even for the same input. Importing revision2 never changes a revision1 instance.
Derived instances cannot be enabled or edited by general tool PUT, enable,
credential or seed writers; these return `definition_pending` where the route
is available. Author another name, or deliberately remove and recreate it:

```sh
locksmith tool delete customer
locksmith tool from-definition customer --definition local.customer --revision 1 \
  --auth-profile none --upstream https://example.com/mcp
```

Deletion uses the existing authority cleanup; old grants/account selections are
not restored by name reuse. Definitions themselves remain immutable. A refused
credential attachment commits no sealed value. Already admitted work and
committed operations retain their existing lifecycle boundaries.

Missing exact revision returns404 / CLI4. Invalid, duplicate-key, oversized,
unknown or unsupported input returns400; local CLI decoding exits2 before
sending invalid files. Server400 maps to the existing CLI generic exit1.
Diagnostics do not echo rejected JSON. Disabled instances are absent from agent
discovery and denied through both native and raw HTTP routes.

## Reference candidates

All three bundled documents use the same schema and validation as customer
inputs. The `builtin.*` namespace accepts only the exact bundled content.
They are descriptive **candidates**, not verified provider implementations:

| File | Descriptive profile | Evidence still required |
| --- | --- | --- |
| [Linear](../../../definitions/linear.json) | OAuth provider; candidate `read` scope | Dedicated eligibility, useful read and actual lifecycle, AGENT-195 |
| [Slack](../../../definitions/slack.json) | User OAuth; candidate public search/history scopes | Eligible app, actual granted scopes and lifecycle, AGENT-196 |
| [Context7](../../../definitions/context7.json) | Separate anonymous and keyed bearer profiles | Dedicated keyed useful calls and invalid/revoked/missing-key behavior, AGENT-200 |

Setup descriptions use the public [Linear documentation](https://linear.app/docs/mcp),
[Slack documentation](https://docs.slack.dev/ai/slack-mcp-server/) and
[Context7 repository](https://github.com/upstash/context7). No token lifetime,
client registration, private Slack access or live success is asserted by these
files. Anonymous Context7 is never a fallback for a failed keyed connection.
Import a reference with, for example,
`locksmith integration import --file definitions/linear.json`.

See the [exact schema and API](../../development/integration-definitions.md)
and [upgrade and recovery](../changes/integration-definitions.md).
