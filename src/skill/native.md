## Native MCP request sequence

For `type: mcp`, use the listing's `/mcp/<connection>` path on the operator's
verified Locksmith listener. Send your Locksmith bearer on every operation, or
your registered client certificate on a listener supporting mTLS. Session IDs
are not credentials. This does not change /skill's optional-auth behavior described above.
Native uses protocol `2025-11-25`, not HTTP /api passthrough.

Use a Streamable HTTP client with automatic call replay and GET renewal disabled.
POST uses `Content-Type: application/json` and
`Accept: application/json, text/event-stream`. Start without a session header:

```json
{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"consumer","version":"1"}}}
```

Consume InitializeResult and retain the response `Mcp-Session-Id`. Later
operations carry that session header and `MCP-Protocol-Version: 2025-11-25`.
Send each JSON object as a separate POST, never a batch:

```json
{"jsonrpc":"2.0","method":"notifications/initialized"}
{"jsonrpc":"2.0","id":1,"method":"tools/list"}
```

Initialized returns 202; requests return JSON or SSE JSON-RPC. Read every listed
tool's complete `inputSchema` and optional `outputSchema` before constructing
arguments. Select an actually listed name and use `tools/call` with
`params: {"name": "LISTED_NAME", "arguments": {}}`, replacing the object with
arguments satisfying that tool's callable schema. This placeholder is not a grant.
Only object arguments are supported. Do not guess names, operations or fields.
Fixed operator context is absent from the callable input schema: never supply
protected keys, even with equal/null values. All-protected tools accept `{}`.
Output schemas describe checked successful structured content; `isError: true`
is a tool error. Connection discovery is not tools/list and grants nothing.

The first successful tools/list pins names/contracts, including an empty list.
Later lists can shrink but cannot add names or changed contracts. After intended
operator repair/grant changes, close the old session and initialize a fresh one.
Every call still checks current grants, selection and observation freshness;
a previously listed tool is not permanent permission. Restart also requires a
fresh operator observation and session. There is no background observation refresh.

Use unique safe integer IDs (absolute value at most 9007199254740991) or nonempty
strings at most 64 UTF-8 bytes without controls. No ID reuse, even after completion.
DELETE with the same identity/session/version retires the session (202). Optional
GET accepts text/event-stream, at most once per session, without Last-Event-ID or
reconnect/resume. Cancellation and disconnect stop owned local work, not submitted
remote effects. Never automatically replay a call or switch account/default/None.

## Native errors and operator repair

HTTP-boundary errors use `error.code`; JSON-RPC refusals use `error.data.code`.
A connection may fail HTTP 401/403/404/408/409/429/503 before a tool response.
Tool refusal uses JSON-RPC -32050. These are not the HTTP proxy repair envelope.

Operators read existing local snapshots first:

```
locksmith --format json tool mcp show <connection> --agent <agent-public-id>
locksmith --format json agent mcp-grants show <connection> --agent <agent-public-id>
locksmith agent credentials list <agent-public-id>
```

- Missing/stale observation: inspect current source/activation, re-observe,
  review changed tools and deliberately replace affected finite grants.
- `tools_list_required`, `tool_not_approved`, `authority_changed`: inspect current
  grants/selection and session pins. Re-fetch/list or use a fresh session after
  intended repair; widening a connection allowlist alone cannot grant a tool.
- Source/activation/conflict errors: read current state, repair the selected
  source, and rebuild intended writes with current source/generation/revision.
- `protected_argument`, `argument_schema`, `value_limit`: use only public fields
  and respect the full merged argument limits, including injected fixed context.

Native supports explicit None or a live sealed StoredBearer selection only.
Env, op/1Password, header and OAuth selections remain HTTP-only. The operator
uses `agent set-credential ... --no-auth`, `--stored-bearer-stdin`, or a deliberate
`--stored-bearer-ref` selection; never supply provider tokens to the consumer.
Selection changes clear affected grants; a saved review alone grants nothing.
Consult the shipped native-tool-review/native-context operator guides for the
exact observation, review and grant preconditions. No implicit fallback.

`tool_outcome_unknown`, submitted-COMMIT uncertainty, timeout after submission,
disconnect or missing outcome cannot establish that no remote effect occurred.
Use existing audit query and server-generated operation/admission IDs for diagnosis:
`native_tool_denied` describes controlled pre-admission refusals;
`native_tool_unknown` describes submitted-COMMIT uncertainty; `mcp_admitted`
precedes submission and `mcp_outcome` can report success/tool_error/not_submitted/
unknown. Diagnostic sinks can fail or omit records. No complete durable history,
remote rollback or safe replay is promised. A deliberate new call can duplicate
an ambiguous effect. A checked result can survive later cleanup/diagnostic failure;
a disconnected peer may never receive it.

### Optional compact MCP

Only use a compact route when authenticated /tools supplies compact_path. Initialize
and list on that exact path; the first list pins inventory and returns search,
describe and invoke. Call search with query (nonblank, at most 256 UTF-8 bytes, no
controls) and optional limit (1–20, default 5). Decode the single JSON text block;
a cursor requires the same original query and effective limit. Search is only a
hint: describe the chosen opaque handle and read its complete input_schema,
output_schema, effect and contract_digest before constructing public arguments.
Call invoke with handle, contract_digest and an arguments object. It uses the
same reviewed tool authority, fixed inputs, committed audit and one dispatch.

Handles/receipts belong to this session and facade; search alone is insufficient.
Do not use standard /mcp sessions on /compact, raw names instead of handles, or
fixed operator inputs. Per-session limits are 32 handles and 32 cursors, sharing
all native session/ID/ingress limits. compact_response_limit means the complete
result cannot fit 16 KiB text/32 KiB encoded result; no schema is truncated. A
single oversized describe/signature cannot be repaired by smaller search pages.
Any deliberate standard-session alternative must never replay an ambiguous call.
compact_cursor_changed needs a fresh search; schema_required needs a full describe.
The same result, cancellation, current-authority and unknown-outcome rules apply.