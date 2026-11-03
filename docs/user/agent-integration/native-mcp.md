# Native MCP agent interface

Use your own Locksmith agent identity over the operator-provided verified TLS
listener. Discover connections with authenticated `GET /tools`; a native entry
has `type: "mcp"`, a path such as `/mcp/sample`,
`protocol_version: "2025-11-25"` and `tool_authority: "none"`.
It is not an HTTP `/api` connection. No provider credentials are supplied to a
consumer. Activation/account selection are configuration facts, not credential
readiness or permission to execute a tool.

This stage supports stateful Streamable HTTP lifecycle only: initialize, ping,
empty tools/list, explicit tools/call denial, cancellation, GET and DELETE.
No tool is callable. Resources, prompts, sampling, elicitation, roots, tasks,
compact, stateless protocols, legacy SSE and stdio are unsupported.

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
JSON-RPC responses. The list is empty. The call returns error -32050 with
`data.code: "tool_not_approved"`; it makes no upstream request. Do not infer
tool approval from the connection grant or account selection.

Use unique safe-integer IDs (absolute value at most 9007199254740991) or nonempty
strings of at most 64 UTF-8 bytes without control characters. Initialization,
outstanding and completed request IDs share a bounded 256-ID ledger; reuse is
409 and exhaustion is 429. Open a new session only after closing the old one.
Valid request params may include `_meta: {"progressToken": ID}` or empty `_meta`
for standard SDK compatibility. Progress is not emitted. Other metadata, task
extensions, arbitrary envelope fields and negotiated client capabilities reject.
No cursor is supported by the empty list.

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
from mcp.shared.exceptions import MCPError

async def main() -> None:
    ca = ssl.create_default_context(cafile=os.environ["LOCKSMITH_CA_FILE"])
    headers = {"Authorization": "Bearer " + os.environ["LOCKSMITH_AGENT_TOKEN"]}
    async with httpx2.AsyncClient(verify=ca, trust_env=False, headers=headers) as http:
        async with streamable_http_client(os.environ["LOCKSMITH_NATIVE_URL"], http_client=http) as streams:
            async with ClientSession(*streams, read_timeout_seconds=5) as session:
                await session.initialize()
                assert (await session.list_tools()).tools == []
                await session.send_ping()
                try:
                    await session.call_tool("unapproved", {})
                except MCPError as error:
                    assert error.code == -32050
                    assert error.data["code"] == "tool_not_approved"
                else:
                    raise AssertionError("unexpected tool authority")

asyncio.run(main())
```

This example makes no useful provider call. The Rust client pin is rmcp3.7.0
with protocol2025-11-25. Consumers should disable expired-session call replay
and GET renewal; the server refuses them. The accepted bounded Rust adapter
provides this policy; see [its contract](../../development/mcp-transport.md).

## Errors and limits

HTTP 400 is malformed protocol/session input, 406/415 is media negotiation,
413 oversized body, 431 oversized headers, 401 invalid/current identity,
403 denied grant/binding/Host/Origin, 404 unavailable session/connection,
408 total request deadline, 409 repeated ID, 429 finite capacity with
`Retry-After: 1`, and 503 unavailable state/activation or shutdown.
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
grants cannot create tool authority in this stage.
