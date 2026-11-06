# Compact native MCP

Compact is an operator opt-in on a manual native connection or a supported
[deliberately promoted local customer pin](../operator/integration-definitions.md). Read authenticated
`GET /tools`: use `compact_path` only when present. The ordinary `path` remains
available. Both require your current Locksmith identity and explicit selected
account. Neither a connection nor the three compact tools grants upstream authority.

Use the normal stateful Streamable HTTP initialization sequence and protocol
`2025-11-25`, then `tools/list`. The compact list contains `search`, `describe`,
and `invoke`. That first successful list pins your current approved inventory,
including an empty inventory. Search cannot add later grants to this session.
Sessions, request IDs, handles and cursors belong to one route and identity;
never move a session between standard and compact paths. Both share process,
agent, connection, stream and request limits.

## Search, describe, invoke

Call these three tools through ordinary `tools/call`. Search arguments:

```json
{"query":"record","limit":5}
```

`query` is required, nonblank, at most 256 UTF-8 bytes and contains no control
characters. Matching is a trimmed, Unicode-lowercase substring of public name,
title or description; ordering is by exact tool name. `limit` is an integer 1–20,
default 5. Search and describe each return one JSON text block in `content`,
without `structuredContent`. Decode that text as JSON:

```json
{"matches":[{"handle":"<32 lowercase hex>","name":"read_record","summary":"Read a record","signature":"(\"key\": string required)","contract_digest":"<64 lowercase hex>"}],"next_cursor":null}
```

A nonnull `next_cursor` is passed as `cursor` with the **same original query
bytes and effective limit**. Changes in observation, grants or the matching
inventory invalidate the cursor. Case/whitespace-equivalent queries still have
different cursor identity. Search summaries may be shortened to 512 UTF-8 bytes;
signatures contain every public top-level property with its exact JSON-quoted
name, declared type and required/optional status. They are hints, not schemas.
Search never creates a described receipt or contacts the upstream.

Describe the chosen handle before invoking it:

```json
{"handle":"<handle from search>"}
```

The decoded result has `name`, `contract_digest`, complete `input_schema`,
`output_schema` (or null), `effect` (`read`, `write` or `mixed`), `usage` and
`limitations`. The input is the public projection of the reviewed contract;
operator-fixed top-level inputs are omitted. An all-protected tool takes `{}`.
The digest still covers the full immutable review, including fixed context.
A successful bounded describe records that digest for this session and handle.

```json
{"handle":"<described handle>","contract_digest":"<described digest>","arguments":{"key":"record-1"}}
```

Invoke returns the ordinary checked upstream MCP call result. It uses the same
current authority, protected-input merge, schema/known-secret validation,
selected account, destination/TLS policy, committed admission audit and single
upstream send as standard MCP. `isError:true` remains a tool error. Describing a
tool is not a reservation: revocation, changed schema/context/account or expired
observation can still refuse invocation. Unchanged eligible handles retain the
standard exact-regrant semantics; a cursor can expire while such a handle remains
valid. No automatic observation, credential fallback or replay occurs.

## Limits and refusals

Each session retains at most 32 opaque handles and 32 cursors; identical handles
and continuation records are reused. Search/describe publish registry changes
only after the complete result fits: at most 16 KiB JSON text and 32 KiB serialized
MCP result, including escaping. No schema or signature is truncated to fit.
A standard-valid contract may be too large for compact. Reducing page size can
help a multi-match search, but cannot fix a single oversized signature or describe.
`compact_response_limit` leaves no new handle/cursor/describe receipt. Deliberate
use of a fresh standard session is possible if that contract fits standard limits;
never switch routes to retry an ambiguous invocation.

RPC refusals have `error.data.code`; native HTTP refusals have `error.code`.
`tools_list_required` means list first. `schema_required` means a matching full
describe is required. `compact_arguments` rejects malformed/extra/null fields;
`compact_reference` rejects unavailable or foreign references;
`compact_cursor_changed` requires a new search; `compact_capacity` needs a new
session. Existing authority, argument, cancellation and result refusals still
apply. Unknown admission/remote outcomes do not prove rollback or justify retry.
Session response-drop retirement is distinct from registry publication.

This bounded facade supports the same finite None/live StoredBearer and
[owner-selected controlled OAuth](../operator/native-oauth.md) tools as
[standard native MCP](native-mcp.md). It does not establish hosted provider
compatibility, tasks, resources, prompts or a model token-efficiency claim.
[Customer pins](../operator/integration-definitions.md) require separate operator
activation; the facade itself never promotes them.

## Operator opt-in and compatibility

For a manual connection, set `"compact":true` in `--mcp-config-file` alongside
`"protocol_version":"2025-11-25"`. For a supported local customer pin, use
`tool activate-definition NAME --if-match REVISION --compact` instead; general
configuration PUTs cannot edit pins. Changing an already promoted pin requires
deactivate then activate with fresh revisions. See the
[activation and repair procedure](../operator/integration-definitions.md).
Omitted/false serializes without the compact field.
Configure before establishing authority: changing the MCP configuration invalidates
connection grants/bootstrap scopes, selections, observations, reviews and per-tool
grants through the existing migration rules. Deliberately restore those and use
fresh sessions. Do not treat this as a cheap routing toggle.

The original compact increment had no new schema migration. A pre-compact
Locksmith CLI could read compact JSON through that increment's daemon.
Its daemon starts on omitted metadata but fails startup with stored `compact:true`,
before HTTP listeners become available; this affects the entire daemon.
Do not downgrade with opted-in rows. The prior-binary test (`tests/native_compact/prior.rs`) checks this against an
actual pre-compact build. Current controlled OAuth also adds schema 17: see its
[whole-daemon downgrade refusal and recovery](../operator/native-oauth.md#upgrade-and-evidence-limits). No transparent downgrade is claimed.

Current customer activation adds schema 18; retain the
[whole-daemon upgrade/recovery cost](../changes/integration-definitions.md).
