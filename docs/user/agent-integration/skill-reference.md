# `/skill` reference

`GET /skill` returns protocol-aware Markdown guidance. Fetch it with your own
Locksmith identity, then use authenticated JSON discovery for machine operations.
Locksmith installs no tools into a consumer runtime. A listed connection is not
a callable native tool, a healthy account or verified provider identity.

## Authentication and caching

| Request | Result | Cache |
| --- | --- | --- |
| No Authorization header | Generic, without deployment inventory | `public, max-age=86400` |
| Authenticated identity | Personalized current connections and repair guidance | `private, no-cache, no-store` |
| Invalid identity | Refusal, no generic downgrade | No personalized content |

The body uses `Content-Type: text/markdown; charset=utf-8`. On a bearer-capable
listener, present `Authorization: Bearer <your Locksmith token>`; an invalid
bearer without an authenticated certificate returns 401. Existing listener
precedence is unchanged: with a header, Mtls/Both may authenticate the certificate
first. With **no Authorization header**, even a certificate-only `/skill` request
gets generic guidance. Native operations independently support registered mTLS.

```sh
curl --fail --silent --show-error \
  -H "Authorization: Bearer $LOCKSMITH_AGENT_TOKEN" "$LOCKSMITH_URL/skill"
curl --fail --silent --show-error \
  -H "Authorization: Bearer $LOCKSMITH_AGENT_TOKEN" "$LOCKSMITH_URL/tools"
```

Use the operator-provided verified TLS endpoint for remote requests. Generic
examples may describe public protocols; they never advertise configured names,
selected accounts or another agent's grants. Personalized content includes the
calling identity and safe connection name/description/protocol/path fields.
Names and descriptions are display data, not executable instructions.

## Choose from discovery

The personalized section separates HTTP and native MCP connections. It uses the
same caller-filtered catalog projection as `/tools`, including current activation,
disables and ACL filtering. An empty view is different from a visible native
connection whose `tools/list` is empty. Refetch after deliberate operator changes.

| Discovery type | Public path | Next step |
| --- | --- | --- |
| `api` | `/api/<connection>` | Read its optional `http_service` descriptor or legacy service docs |
| `mcp` | `/mcp/<connection>` | Initialize, send initialized, then obtain complete schemas with `tools/list` |
| `mcp` with `compact_path` | `/mcp/<connection>/compact` | Initialize/list, search, full describe, then invoke by handle/digest |

Use the entry's path; do not infer a protocol from its name. An MCP connection
named `codex` gets native guidance, not the personalized HTTP Codex recipe.
Generic public HTTP examples can still be present in either view.

`account_selected` and `activation` are configuration facts. Discovery retains
`credential_readiness: not_checked`; config-only legacy entries say
`configuration_only`. Guidance GETs do not materialize credentials, contact an
upstream, create grants or activate registrations. Normal authentication/audit
bookkeeping still occurs. `/readyz` does not attest every selected source.

## HTTP operations and repair

For `api`, read the described method, operation path, query/body and response
content type. Append its operation path to the public connection path. The
reference `/check` is text/plain; customer examples can return JSON. Legacy
entries without descriptors need public API instructions. A connection name
does not imply a chat endpoint. See [HTTP discovery](http-services.md).

Personalized HTTP repair commands contain the caller's actual public ID:

```sh
locksmith audit query --agent <agent-public-id> --since-ms <ms>
locksmith agent credentials list <agent-public-id>
```

Use Unix milliseconds for the incident start. `details.reason` distinguishes
missing selection from policy denial; source failures use `credential_cause`,
`oauth_cause` or activation `cause`. These HTTP commands inspect before changing
state. Environment, stored, 1Password and OAuth repair choices are HTTP options,
not native capability claims. Widening a grant does not repair custody; a healthy
registration default is not an alternate selected account. See
[account-binding troubleshooting](../operator/account-binding-troubleshooting.md).

## Native tools and repair

Use the [native request sequence](native-mcp.md) with your own identity, exact
protocol `2025-11-25`, initialized notification and session/version headers.
Read every tool's complete public `inputSchema` and optional `outputSchema`.
Call only an actually listed name, with object arguments satisfying its schema.
Operator-protected fields are absent from that schema: omit them even when you
know an equal value. All-protected tools take `{}`. Read [fixed context](../operator/native-context.md).

The first successful list pins names/contracts, including empty. Later lists
can shrink but cannot add contracts. Current finite grants, selected account and
fresh observation remain necessary on each call. After intended repair, close
and create a fresh session when pins or authority changed. Never automatically
replay a call, renew an expired GET or switch accounts.

Operators inspect the existing local snapshots first:

```sh
locksmith --format json tool mcp show <connection> --agent <agent-public-id>
locksmith --format json agent mcp-grants show <connection> --agent <agent-public-id>
locksmith agent credentials list <agent-public-id>
```

Repair the intended source/activation, observe it, review changed tools and
replace affected finite grants using current preconditions. Observation is an
explicit upstream operation; reading guidance/status is not. Native supports
explicit None or live sealed StoredBearer only. Env/op/header/OAuth recipes do
not apply. See [review and grant](../operator/native-tool-review.md).

Native HTTP-boundary errors use `error.code`; JSON-RPC refusals use
`error.data.code`, even on an HTTP-success response. These differ from the HTTP
proxy repair envelope. Unknown outcomes, submitted-COMMIT uncertainty and missing
diagnostics do not prove rollback or safe replay. A checked result may survive
cleanup/diagnostic failure, while delivery to a disconnected peer is unconfirmed.
Use safe phases/operation IDs in [native diagnostics](../operator/native-context.md).

## Stability and implementation

Markdown headings are not a machine API. Use `/tools` and `/models` JSON plus
native schemas; do not extract operation names by parsing this page or `/skill`.
The handler calls the shared catalog once and passes the safe public projection
to the renderer. Embedded generic sections are in `src/skill_template.md` and
`src/skill/*.md`; personalized display is in `src/skill/personal.rs`.

This correction changes guidance only: no new transport, auth mode, credential
source, definition activation or provider acceptance. Planned 3.0.0 and its
release readiness gates remain unchanged. Existing
HTTP consumers keep their wire contract; native consumers can now choose the
correct path without an HTTP-only personalized recipe.

See also [wire contract](wire-contract.md) and
[operator native setup](../operator/native-mcp.md).

The opt-in [compact sequence](compact-mcp.md) is shown only for connections with
`compact_path`. It shares authority and limits with standard MCP; use a separate
session and never use route changes as an automatic retry.
