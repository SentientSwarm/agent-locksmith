# Bounded native MCP transport prerequisite

AGENT-198 adds [locksmith-mcp-transport](../../crates/mcp-transport/README.md),
a reusable adapter for rmcp's public `StreamableHttpClient` hook. It is not
wired into either Locksmith binary. AGENT-202 owns native daemon integration;
[AGENT-199 sessions](mcp-sessions.md) own session allocation/recovery. Existing HTTP/OAuth behavior,
configuration and the root 2.8.0 version are unchanged. No deployment or
migration is needed for this isolated library.

The design starts from accepted HTTP/OAuth `10a0d8b` and the S1 counterexample
at research `087ea143d9604a9450949666ed6390d55732b931`:
`proofs/native-mcp/S1/tests/json_limit.rs`. The original SDK accepts over32KiB
of JSON despite a16-byte SSE limit. Its observation remains in `tests/original.rs`
(with only the proof-crate error alias replaced). `tests/regression.rs` asserts
refusal using the bounded client; the same assertion failed with stock reqwest.
A passing observation of the old fault is not a safety pass.

## Byte flow and ownership

1. The adapter constructs its own reqwest client. TLS verification stays on;
   optional roots add trust. Redirects, environment proxies, compression,
   connection pooling and retries are disabled. HTTP/1.1 only.
2. Length and encoding headers can refuse a body without reading it. For
   accepted bodies each received chunk is checked against chunk size/count
   and cumulative response bytes before copying or forwarding to a parser.
3. JSON success and error bodies use a collector with finite configured
   capacity. EOF is required before decoding, including trailing whitespace.
   An allocation-free lexical scan limits nesting and structural/value work
   before serde builds the SDK message. HTTP errors retain bounded JSON-RPC
   errors, 401/403 challenge information and attached-session404 semantics.
4. SSE uses the same cumulative response accounting, then a raw block/event
   guard before the pinned SSE parser. Comments and empty blocks count.
   Parsed data receives the JSON preflight before SDK JSON decoding. No
   detached reader or buffering channel is added. Dropping the future/stream
   drops the response; terminal errors release it.
5. The supplied SDK transport disables session reinitialization and SSE retry,
   uses four concurrent POSTs and an eight-entry channel. A call is never
   automatically replayed. These queue settings are not the AGENT-199 session
   capacity repair.

The adapter atomically permits only one GET attempt per client/clone group.
Each explicit `client.transport(...)` creates its own fresh GET budget. Direct
trait calls share the original client's budget; create a new client to start
another deliberate stream. A failed or canceled GET still consumes its attempt.
This guard is necessary because rmcp3.7.0 can reconnect its common GET before
consulting the retry policy, or honor a server `retry` field at EOF. Neither
path may renew network reads or reset limits through the supplied transport.

A bound on a streaming response covers the bytes actually consumed during
that HTTP response, without resetting for events. Consumers can drop after a
useful event: an unread tail is neither buffered nor claimed fully validated.
GET streams have the same finite lifetime. A server effect can occur before
an oversized response or cancellation: rejection cannot undo it.

## Configuration and supported modes

Construct `Client::new(Limits, extra_roots)` and use `Client::client_config()`
with `client.transport(uri, bearer)`. The application installs its normal
Rustls crypto provider first. Protocol2025-11-25 is the supported version;
other initialization/negotiated versions and version headers fail explicitly.
No `locksmithd` YAML option or CLI switch is introduced by this prerequisite.
`Limits` supports serde, rejects unknown fields and validates every constructor.
All fields must be supplied when deserializing; `Limits::default()` supplies
these Rust defaults:

| Field | Default | Hard ceiling / meaning |
| --- | --- | --- |
| response_bytes | 262144 | 8388608; cumulative body payload bytes |
| chunk_bytes | 262144 | 8388608; one reqwest-delivered chunk, not a TCP packet |
| chunks | 8192 | 65536; delivered body chunks |
| event_bytes | 65536 | 8388608; raw SSE block including delimiters/comments |
| events | 128 | 65536; blank-line-terminated SSE blocks, including empty ones |
| json_depth | 32 | 64; nested arrays/objects |
| json_units | 8192 | 65536; structural delimiters plus string/scalar starts |
| timeout_ms | 10000 | 120000; total request through body consumption |
| connect_timeout_ms | 3000 | At most timeout_ms |

Zero is invalid, not unlimited. The SDK event-size argument can only lower
`event_bytes`. JSON units include every `{ } [ ] : ,`, quoted-string start,
and unquoted scalar start outside strings; escaped quotes and delimiters
inside strings do not count. SSE JSON units accumulate across data messages.
Strings cannot expand beyond bounded encoded input; SDK containers and schema
JSON are also bounded by units/depth. This adapter does not compile schemas,
evaluate regexes, fetch references or validate tool arguments. Passing a
schema through this layer does not approve it; later admission owns that work.

Chunked and close-delimited responses work without trusting Content-Length.
Advertised excess can fail before any body read. Invalid/contradictory/truncated
HTTP framing is refused: the adapter rejects Transfer-Encoding with
Content-Length and any transfer coding other than a single `chunked` value;
the HTTP stack handles malformed/truncated framing. With falsely short Content-Length, only
the declared body belongs to the response; surplus bytes are discarded with
the unpooled connection, not parsed as a second reply. The adapter does not
claim to inspect bytes the HTTP stack excludes.

Non-identity Content-Encoding is refused before decoding, including gzip,
brotli, deflate and zstd. Redirects of every status are refused. Resumption
(`Last-Event-ID`), automatic SSE renewal and alternate protocol versions are
unsupported. Media types are application/json or text/event-stream with an
optional UTF-8 charset parameter. Indefinite streams, compressed servers,
HTTP/2-only endpoints and redirect-dependent endpoints require an explicit
future support change; raising a byte cap does not enable them.

## Diagnostics and resource evidence

Transport faults are static `mcp_transport_*` codes: `response_bytes`,
`chunk_bytes`, `chunks`, `event_bytes`, `events`, `json_depth`, `json_units`,
`json_syntax`, `sse`, `sse_truncated`, `content_encoding`, `content_type`,
`framing`, `transfer_encoding`, `get_renewal_unsupported`,
`deadline`, `http`, `redirect`, `http_status`, `auth`, `auth_header`,
`session_header`, `protocol_version`, `reserved_header`, `resume_unsupported`,
`url`, `invalid_limits` and `client_setup`. SSE wraps the same codes. No
response-body preview or request URL is placed in adapter error text.
Auth challenges and legitimate bounded JSON-RPC error messages remain protocol
data: callers must not blindly log their debug representation or whole results.
The selected SSE dependency has its optional tracing feature disabled.

On a limit error, inspect the configured limit and request outcome; do not
blindly retry a possibly executed tool. Correct endpoint/protocol/encoding
setup for unsupported modes. Reconnect deliberately after an expired session.
A bounded cap increase requires resource review; it never repairs a framing
error or grants authority. SDK cancellation remains an explicit protocol
notification, not proof of reversing an upstream action.

`Client::metrics()` returns aggregate received/admitted byte counts, chunk
count, incoming-chunk and retained-payload high-water marks, and active body
owners. These are adapter observations, not a process-global memory ceiling.
The JSON collector reserves `response_bytes`; SSE parser vectors/strings,
SDK copies, HTTP header buffers, reqwest/hyper/TLS/socket buffers, allocator
rounding and the already-delivered chunk remain distinct allocations. A
2KiB incoming chunk under a16-byte chunk cap yielded2048 received,0 admitted,
0 retained and0 active body owners. This demonstrates refusal before adapter
copy, not prevention of the upstream chunk allocation.

## Verification and gate boundary

The crate tests cover whole-body and lexical boundaries, many small chunks,
comments/events, immediate CR/LF/CRLF boundaries and split UTF-8, false/missing length, malformed/truncated
payloads, error bodies, unsupported encoding, redirects, deadlines, drop and
recovery. `sdk_smoke` launches a separate Python TLS receiver and uses actual
rmcp initialize/list/call/cancel/close with synthetic auth/session/version
checks. It counts tool effects separately from response acceptance: the large
reply has one effect and no replay; a subsequent permitted call works.
`sdk_renewal` uses that receiver to verify exactly one common GET after a body
limit, deadline or server `retry: 0` field. Direct clones share the atomic
attempt budget; a deliberately constructed new transport gets a fresh one.
The deadline case observes an active GET, holds the receiver body beyond the
finite request budget, and verifies expiry/cleanup before service cancellation.

Run the [crate commands](../../crates/mcp-transport/README.md) as well as the
root locked tests, strict Clippy, fmt, binaries and saved process smoke.
CI includes the separate crate commands; GitHub Actions execution itself is
not established by a local run. Independent exact-candidate QA/review evidence
is required. This repair alone does not turn G1 green: AGENT-202 and linked
native two-client/provider/schema/migration evidence remain required. G2 still
needs AGENT-205. Full native/provider acceptance remains separate from this
public source projection; no release readiness is claimed.

The public projection preserves the accepted adapter bytes; its current
receiving checks and Linux CI remain pending at source preparation. Historical
SDK/wire/Python checks above do not establish execution on this public tree.
CI uses the existing root target directory for both independent manifests.
