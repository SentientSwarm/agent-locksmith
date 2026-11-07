# Native MCP agent interface

Supported local customer pins use the [dedicated operator activation workflow](../operator/integration-definitions.md) before separate account selection and finite tool grants. The agent interface never promotes a definition.

Use your own Locksmith agent identity over the operator-provided verified TLS
listener. Fetch authenticated [`/skill`](skill-reference.md) for protocol-aware
guidance, then use JSON discovery rather than Markdown headings. Discover connections with authenticated `GET /tools`; a native entry
has `type: "mcp"`, a path such as `/mcp/sample`,
`protocol_version: "2025-11-25"` and `tool_authority: "reviewed_per_agent"`.
It is not an HTTP `/api` connection. No provider credentials are supplied to a
consumer. Activation/account selection are configuration facts, not credential
readiness or permission to execute a tool.

Manual None, sealed-bearer and deliberately owner-selected
[controlled OAuth](../operator/native-oauth.md) or
[hosted Linear](../operator/hosted-linear.md) accounts support finite reviewed tools. Each
call requires the current selected account, current reviewed grant and a fresh
operator observation (less than60 seconds old, from this daemon run). The list
is empty when no tools are granted; stale observations require operator repair.
Resources, prompts, sampling, elicitation, roots, tasks, dynamic context,
stateless protocols, legacy SSE and stdio are unsupported. An explicit
[compact facade](compact-mcp.md) adds search/full describe/invoke on the conditional
`compact_path`; standard sessions and schemas remain available.

## Request sequence

Every HTTP operation authenticates with `Authorization: Bearer AGENT_TOKEN`, or
your registered client certificate on an mTLS-capable listener. Session IDs are
not authentication. They are bound to the agent, connection and current authority
revision; another agent or endpoint cannot use or close them.

POST uses `Content-Type: application/json` and
`Accept: application/json, text/event-stream`. Start without a session header:

```json
{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"consumer","version":"1"}}}
```

Read the response's `Mcp-Session-Id` and consume its InitializeResult. The result
advertises only tools, with no list-change capability. Subsequent requests use
that session header and `MCP-Protocol-Version: 2025-11-25`. Send:

```json
{"jsonrpc":"2.0","method":"notifications/initialized"}
```

It returns 202 with no body. Then:

```json
{"jsonrpc":"2.0","id":1,"method":"ping"}
{"jsonrpc":"2.0","id":2,"method":"tools/list"}
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"unapproved","arguments":{}}}
```

Each line is a separate POST, not a JSON batch. Requests return JSON or SSE
JSON-RPC responses. The list contains only effective reviewed tools and their complete callable schemas. The
example unapproved call returns -32050 with `data.code: "tool_not_approved"`.
Calling before a successful list returns `tools_list_required`. Neither sends a
tool upstream. Do not infer tool approval from connection/account selection.

The first successful list pins the returned names and exact contracts, even if
empty. Later lists can shrink but cannot add names or changed contracts. A new
grant needs a new session. Existing pins still require current grants on every
call; revocation/drift does not become permission when inventory returns.
Deliberate regrant of an identical previously pinned contract can be effective.

Use unique safe-integer IDs (absolute value at most 9007199254740991) or nonempty
strings of at most 64 UTF-8 bytes without control characters. Initialization,
outstanding and completed request IDs share a bounded 256-ID ledger; reuse is
409 `request_id_reused`. A session also has a message budget (default 256)
that counts notifications. Exhausting either budget returns 429 `session_limit`
(or `request_id_limit`) with `Retry-After: 1` and closes the session; the next
request on it returns 404 `session_unavailable`, so open a new session.
Otherwise, open a new session only after closing the old one.
Valid request params may include `_meta: {"progressToken": ID}` or empty `_meta`
for standard SDK compatibility. Progress is not emitted. Other metadata, task
extensions, arbitrary envelope fields and negotiated client capabilities reject.
The finite list has no cursor.

`notifications/cancelled` accepts `params: {"requestId": ID}` and optional bounded
`reason`. It returns 202 and only addresses that authenticated session. DELETE
with the same identity/session/version returns 202 and retires the session.
GET additionally needs `Accept: text/event-stream`; only one non-resumable GET
is permitted per session. `Last-Event-ID`, reconnect/resume and reinitialization
are refused. Do not automatically replay `tools/call` or renew an expired GET.

Dropping an unfinished response retires its session. Consuming the final
InitializeResult keeps the session valid without requiring an extra EOF read.
Restart, expiration, revocation, relevant policy/account changes and registration
revision changes require a fresh session. Cancellation stops owned local work;
it is not a promise to undo an already-submitted remote or database effect.

## Pinned Python client

The independent Python API uses `mcp==2.3.0` and `httpx2==2.16.0`. Supply
`LOCKSMITH_NATIVE_URL`, `LOCKSMITH_CA_FILE` and `LOCKSMITH_AGENT_TOKEN` privately.
The full tested environment is in
[requirements.txt](../../../tests/native_process/requirements.txt).

```python
import asyncio
import os
import ssl
import httpx2
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

async def main() -> None:
    ca = ssl.create_default_context(cafile=os.environ["LOCKSMITH_CA_FILE"])
    headers = {"Authorization": "Bearer " + os.environ["LOCKSMITH_AGENT_TOKEN"]}
    async with httpx2.AsyncClient(verify=ca, trust_env=False, headers=headers) as http:
        async with streamable_http_client(os.environ["LOCKSMITH_NATIVE_URL"], http_client=http) as streams:
            async with ClientSession(*streams, read_timeout_seconds=5) as session:
                await session.initialize()
                tools = (await session.list_tools()).tools
                for tool in tools:
                    print(tool.name, tool.input_schema)
                name = os.environ.get("LOCKSMITH_TOOL_NAME")
                if name is not None:
                    import json
                    assert any(tool.name == name for tool in tools)
                    # Construct these arguments from the returned complete schema.
                    arguments = json.loads(os.environ["LOCKSMITH_TOOL_ARGUMENTS"])
                    result = await session.call_tool(name, arguments)
                    print(result)

asyncio.run(main())
```

Set the optional name/arguments only for a deliberately selected tool; do not
automatically replay exceptions or ambiguous results. The Rust client pin is rmcp3.7.0
with protocol2025-11-25. Consumers should disable expired-session call replay
and GET renewal; the server refuses them. The accepted bounded Rust adapter
provides this policy; see [its contract](../../development/mcp-transport.md).

## Errors and limits

HTTP errors carry `{"error":{"code","message"}}`. Read `code`:

| HTTP | Meaning | `code` values |
|---|---|---|
| 400 | Malformed protocol/session input | `protocol_version`, `session_required`, `initialize_has_session`, `initialization_incomplete`, `unexpected_body`, `query_unsupported`, `resume_unsupported`, `duplicate_header`, `host_required` |
| 401 | Invalid or no longer current identity | `invalid_credential` (bearer, shared agent envelope), `agent_identity_required`, `agent_inactive` |
| 403 | Denied grant, binding, Host or Origin | `connection_not_allowed`, `account_selection_required`, `host_denied`, `origin_denied` |
| 404 | Unavailable session or connection | `session_unavailable`, `session_closed`, `connection_unavailable`, `authority_changed`, `compact_unavailable` |
| 405 / 406 / 415 | Method or media negotiation | `method_not_allowed` / `accept` / `content_type` |
| 408 | Total request deadline or cancellation | `request_deadline`, `request_cancelled` |
| 409 | Repeated request ID | `request_id_reused` |
| 413 / 431 | Oversized body / headers | `request_body_limit` / `headers_too_large` |
| 429 | Finite capacity, with `Retry-After: 1` | `session_limit`, `request_id_limit`, `ingress_limit` |
| 503 | Unavailable state or activation, or shutdown | `connection_not_active`, `native_store_unavailable`, `native_scope_unavailable`, `native_boundary_missing`, `invalid_native_configuration`, `shutting_down` |

Other refusals from the protocol layer use `protocol_request_refused`.
JSON-RPC -32700/-32600/-32601/-32602 mean parse/envelope/method/params refusal.
Tool denial is -32050. Errors reflect only valid bounded request IDs; invalid
or oversized IDs become `id: null`. Errors are bounded and do not expose
upstream auth data.

Absent Origin is allowed; present Origin must match the operator's exact
allowlist. Host must match its configured authority. Query strings, duplicate
security headers, batches, null/float/object IDs and duplicate JSON members
reject. Native budgets and compatibility costs are listed in
[finite limits](../../development/native-mcp.md). Use the
[operator guide](../operator/native-mcp.md) to diagnose configuration; widening
connection ACLs alone cannot create tool authority.

## Arguments, results and uncertain effects

Read the full input schema before constructing object arguments; omitted arguments
mean `{}`. Objects are closed, required fields apply, and nested types, array and
Unicode-scalar string lengths, enum/const and numeric bounds are enforced.
Integer fields require a parsed JSON integer (`1.0` is not an integer here).
Operators can protect fixed top-level inputs. Their properties and required
entries are absent from the callable schema; never send those keys, even with
equal or null values (`protected_argument`). Locksmith injects the reviewed
values and validates the complete upstream input. All-protected tools take `{}`.
Arguments after injection are at most32KiB, depth16 and4096 values. Unsupported schema features
never enter a reviewed manifest; no references are fetched.

Results support at most16 text blocks, each16KiB, plus optional object
`structuredContent` and boolean `isError`, within32KiB total. Successful output
schemas require matching structured content. Valid `isError: true` remains a
tool error. Resource links, embedded resources, images, audio, tasks and extra
metadata are refused. Known selected-token echoes are withheld; no general DLP
claim is made.

One original ingress deadline spans auth/body, preparation, final database
admission, call and cleanup (at most10s). Admission must commit before one tool
submission. An invalid/oversized/secret-bearing result after submission returns
`tool_outcome_unknown`: a remote effect may already exist. Timeout, cancellation,
disconnect and missing outcomes have the same uncertainty. No automatic retry
or fallback occurs. A deliberate new call can duplicate that effect. The
operator can correlate safe `mcp_admitted`/`mcp_outcome` audit records using their
server-generated operation/admission ID; arguments, RPC/session IDs and provider payloads
are not audit fields.

See [safe phases and operator repair](../operator/native-context.md) for denied,
uncertain-COMMIT and unavailable-diagnostic evidence. A checked result survives
later cleanup/diagnostic failure while the handler remains owned; response
delivery after disconnect is unconfirmed.
