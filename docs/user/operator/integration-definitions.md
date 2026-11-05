# Author integration definitions

This offline authoring stage saves a strict, immutable definition and creates a
**disabled** native connection pinned to its exact revision and content digest.
Importing does not contact a provider, execute a workflow, obtain credentials,
select an account, grant access or approve tools. The pin is configuration,
not evidence that a provider works. Ordinary agent credentials cannot author it.

Full AGENT-203 remains pending accepted Linear (AGENT-195), Slack (AGENT-196)
and keyed Context7 (AGENT-200) contracts. Operator/live setup (AGENT-194) is also
unaccepted. Consent, promotion, durable refresh, tool review and dispatch remain
separate work (204–208). This feature does not accept G0/G1 or release readiness.

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
