# Review and grant native tools

For owner-selected controlled OAuth, see [native OAuth accounts](native-oauth.md).
Manual hosted Linear accounts use the [fixed hosted profile and selected catalog](hosted-linear.md); they use the same review/grant interface.

Operators can observe, inspect, review and grant a finite set of MCP tools for
an existing agent's explicit account. Agents can list and call only that current
intersection. The first successful list pins its names/contracts for the session,
including an empty list. New contracts need a new session. See the
[agent workflow](../agent-integration/native-mcp.md).

Start with [native connection/agent setup](native-mcp.md) and the existing
operator credential/admin socket. Eligible `mcp_streamable_http` tool connections are enabled and fully activated:
either manual connections or supported local customer pins promoted through the
[dedicated activation workflow](integration-definitions.md). This review interface
cannot itself activate or edit a pin. No provider consent,
identity verification or external readiness is inferred.

Authenticated [`/skill`](../agent-integration/skill-reference.md) now preserves
that protocol/path distinction. Its connection table is not a tool grant or
source-health check. Guidance GETs do not observe or repair an upstream; operators
use the explicit read/observe/review/grant commands below. Consumers receive only
their own Locksmith identity and callable public schemas, never custody inputs.

## Select an account and trust

Use an exact agent public ID. Select None deliberately:

```sh
locksmith agent set-credential AGENT_ID sample --no-auth
```

Or ingest a bearer through stdin, never as an argument. The daemon seals it with
`LOCKSMITH_CREDENTIAL_SEALING_KEY` and returns only a new opaque reference:

```sh
locksmith agent set-credential AGENT_ID sample --stored-bearer-stdin
```

Provide one UTF-8 value on stdin (1–8192 printable ASCII bytes, no spaces or
controls; one terminal newline is removed). Explicit bearer intent replaces
an existing header-shaped selection. The older stored-value API still inherits
header shape when neither `bearer: true` nor an explicit header is supplied.
The sealed insert and selection commit together; a refused write leaves no
new sealed row. Selecting a shared handle is deliberate:

```sh
locksmith agent set-credential SECOND_AGENT_ID sample --stored-bearer-ref CS_REFERENCE
```

That reference must be live. Rotating one selection preserves a handle still
selected elsewhere. Env, op, legacy OAuth selections and stored-header accounts remain HTTP-only.
Controlled and hosted OAuth require their separate owner-bound selection flows linked above.

Upstreams must use verified HTTPS. Optional restart-only extra trust roots:

```yaml
mcp:
  upstream_ca_bundle: /private/config/upstream-ca.pem
```

This adds trust roots, without disabling hostname verification. The bundle is
bounded to 1 MiB and must contain certificates. Normal system roots remain.
Every resolved address is checked and the connection is pinned to that approved
set for the whole attempt. Private, loopback, ULA and CGNAT addresses require
`allow_private_destination: true` in the connection's MCP config. Link-local,
metadata, mapped IPv6, multicast, unspecified, documentation and reserved/special
ranges remain refused. Current local interface addresses paired with an active
daemon listener port are refused, including assigned ephemeral ports. Unrelated
approved addresses sharing that port remain eligible. Unresolved enabled
listeners temporarily refuse observation. External NAT/proxy aliases not
established by local address/configuration are outside automatic self detection.
No redirects, proxies, compression, discovery fallback or automatic retry.

## Observe, inspect and review

`--format json` is a global CLI option. All writes take strict JSON from
`--file PATH` or `--file -` (stdin). Duplicate/unknown members and missing
preconditions are errors. GET never contacts an upstream.

```sh
locksmith --format json tool mcp show sample --agent AGENT_ID > snapshot.json
```

Copy `source` and `observation.generation` into `observe.json`:

```json
{"source":{"instance":"FROM_GET","revision":1,"account_key":"FROM_GET","agent_epoch":1},"generation":null}
```

Use the exact returned numbers/strings. `generation: null` is valid only when
no observation exists. A later attempt must echo the latest generation.

```sh
locksmith --format json tool mcp observe sample --agent AGENT_ID --file observe.json > observed.json
```

Observation performs initialize, initialized notification and paginated list
through the bounded transport. It never calls tools. Complete success publishes
one manifest; errors, incomplete pages and deadlines cannot publish a partial
one. A newer attempt supersedes both late old success and late old failure.

Inspect each `observation.manifest.tools` entry, its complete `tool` description,
schemas and `observed_digest`. To review one, create `review.json`:

```json
{"source":{"instance":"FROM_GET","revision":1,"account_key":"FROM_GET","agent_epoch":1},"generation":"FROM_OBSERVE","name":"read_record","observed_digest":"FROM_OBSERVE","effect":"read"}
```

```sh
locksmith --format json tool mcp review sample --agent AGENT_ID --file review.json > reviewed.json
```

A successful review returns `contract_digest` for the immutable reviewed contract,
not `observed_digest`. For example (all uppercase strings below are illustrative
placeholders, not usable digests):

```json
{"contract":{"tool":{"name":"read_record","inputSchema":{"type":"object","properties":{},"additionalProperties":false}},"context":{},"effect":"read","retry":"never"},"contract_digest":"REVIEWED_CONTRACT_DIGEST","prepared_only":true,"callable":false}
```

Copy `reviewed.json`'s top-level `.contract_digest` into the grant entry's
`.contract_digest`; the name is `.contract.tool.name`. Keep the complete returned
contract for inspection. `prepared_only: true` and `callable: false` do not grant
agent execution authority.

Effect is your declaration: `read`, `write` or `mixed`. Provider annotations
cannot set it. Optional fixed nonsecret `context` is covered in the
[context and diagnosis guide](native-context.md); retry is always `never`. Reviews are
immutable content-addressed records; an exact repeat returns the same digest.

## Grant or revoke finite tools

Continue with [finite grant preparation and revocation](native-tool-grants.md).
Use the review response's `contract_digest` and current grant-show `source`,
`observation.generation` and `grant_revision`.

## API, limits and upgrade

The same authenticated operator API works over UDS and admin HTTPS:

| Method | Path below `/admin/operator` | Body |
|---|---|---|
| GET / POST | `/tools/{connection}/mcp/observations/{agent_id}` | POST: `source`, `generation` |
| PUT | `/tools/{connection}/mcp/reviews/{agent_id}` | `source`, `generation`, `name`, `observed_digest`, `effect`, optional `context`, explicit `contract_policy` and `input_restriction` for opted-in v2 |
| GET / PUT | `/agents/{agent_id}/mcp-grants/{connection}` | PUT: `source`, `generation`, `revision`, `tools` |

Stored ingestion uses PUT `/agents/{agent_id}/credentials/{connection}/credential`
with `{ "value": "PRIVATE_STDIN_VALUE", "bearer": true }`; never save real values
in example files/logs. Shared live selection uses the ordinary selection route
with `auth_spec: {kind: stored_bearer, secret_ref: ...}` and
`require_live_bearer: true`.

Default full-catalog observation admits at most 32 tools in a 48 KiB manifest
envelope. Explicit [finite-v2 registration selection](native-contract-policy.md#explicit-customer-catalog-selection)
and [hosted profile selection](hosted-linear.md#selected-catalog-and-wire-policy)
scan a complete catalog of at most 256 names, publish at most 32 explicitly selected
full contracts within that same envelope, and report total/selected/omitted counts.
All modes retain four pages, 1 MiB aggregate
initialize/list response bytes, 256 KiB per response and 64 KiB per SSE event.
Eight operations share one process budget. JSON write bodies are at most64 KiB
with10s body deadline, followed by one10s operation deadline including DB/DNS/
network/publication. The same daemon owner registers each write before body buffering; stalled bodies
do not take operation slots. Earlier operator authentication is separate. No timeout
resets per page. Cleanup attempts DELETE within that deadline; 405 does not
confirm remote deletion. Submitted SQL/remote/OS-resolver work is not rolled back.

The [supported schema and review contract](../../development/native-tool-review.md)
is deliberately finite. The default is v1; operators can explicitly select
[finite-v2](native-contract-policy.md) for bounded metadata, scalar input defaults,
64-value enums and separately reviewed empty arguments. Unsupported keywords/tool metadata in a selected tool
refuse the whole observation. None/bearer/controlled registrations select the entire catalog by default;
explicit finite-v2 registration selection may use the same complete bounded scan
and omission accounting. Hosted profiles may omit unselected tools under their explicit
profile policy and lossless structural checks. Selected bearer echoes in decoded keys/strings also refuse it;
this is known-secret screening, not general DLP.

The original migration 0014 started with zero tool preparation and preserved existing accounts,
HTTP authority, definitions and OAuth recovery state. Follow the
[consistent backup/rollback procedure](../changes/native-mcp.md) before upgrade.
Schema13 binaries refuse upgraded state before listeners. Restart retains
historical observations/reviews/grants but requires fresh observation. The original
Stage B added no migration: schema-14 stage A binaries could still open that database,
but could not execute those calls. Current controlled OAuth adds schema 17; follow
its [whole-daemon downgrade and repair guidance](native-oauth.md#upgrade-and-evidence-limits). Back up before changing binaries; either restart
invalidates observation freshness. This ships in 3.0.0 as additive work, without
full206/provider acceptance.

## Staged API mapping

This is the implemented preparation interface, rather than a claim of parity
with earlier draft API sketches. There is no `/mcp/discover` endpoint or writable
`account_ref`: `--agent` selects the subject agent, its existing explicit account
binding is joined by the server, and returned `source.account_key` is echoed as
a precondition, never used to choose a different account.

Reviews use `/tools/{connection}/mcp/reviews/{agent_id}` with the tool `name` in
the strict body, rather than `/reviews/{tool}`. Optimistic concurrency uses the
required body `source` and observation `generation`, plus grant-set `revision`
for replacement. HTTP `If-Match` is not the interface. Echo exact returned
preconditions; an absent/null field is not a wildcard or alternate selector.
This staged route shape does not add OAuth or definition activation.

Current customer activation adds schema 18 and a whole-daemon prior refusal; see
[definition upgrade/recovery](../changes/integration-definitions.md). Earlier
schema 14/17 statements above describe their original increments. Hosted Linear
adds schema 19 and prior whole-daemon refusal; follow its
[upgrade and recovery guidance](hosted-linear.md#refresh-failures-and-upgrade).
