# Bounded MCP session ownership prerequisite

AGENT-199 extends the separate [MCP transport library](../../crates/mcp-transport/README.md)
with `sessions::Pool<T>` and per-request `Scoped<T>` managers. It is an isolated
production prerequisite: neither binary exposes native MCP yet. AGENT-202 owns
daemon composition, HTTP error mapping and migration. Root versions, installed
services, existing HTTP/OAuth authority and credentials remain unchanged.

## Integrating verified authority

Create one shared pool for the process and all MCP routes. After authenticating
and reading the current authoritative snapshot, call `pool.scoped(scope,
metadata, cancellation)`. `Scope` contains a non-reused owner identity, logical
connection identity and authority fingerprint, each nonempty and at most256
bytes. These are verified application values, never client-selected values or
credentials. Use the existing agent public identity and registration/binding
identity; same-account token rotation should not change authority. Metadata can
hold the application's existing session, schema and admission state.

Pass that scoped manager to rmcp's `StreamableHttpService` for this HTTP request.
For an existing ID, `metadata`/`has_session` require the same owner/connection and
current fingerprint. Another owner cannot use or retire the victim's session.
A changed fingerprint cancels the old session. On a failed current-authority
read with an independently verified identity, call `pool.invalidate(owner,
connection)`. Lifecycle changes should also invoke that method. A forged or
unknown bearer must not be used to invalidate another owner's session.

The embedding layer still validates grants, selected account, tool/schema and
arguments on every admission, records the final audit boundary and supplies
HTTP body/header/request-ID limits. This library does not authenticate, hash
arbitrary application state, refresh credentials or authorize tools. Preserve
compatible approved tools across unrelated schema changes; don't turn the
fingerprint into a token-version or entire-discovery invalidation shortcut.
Use stateful protocol2025-11-25 service configuration and reject unsupported
stateless/discovery modes in the embedding route. Restore/event stores/replay
are unsupported here. Never retry an ambiguous tools/call.

## Capacity and completion

Reservation and SDK creation share a short synchronous critical section. A full
pool returns typed `Error::Capacity` before `create_local_session` or worker
spawn. Initializing, active and retiring entries all consume capacity. There is
no reservation wait queue. After invalidation, an explicit new initialization
may be refused while cleanup is still in progress; wait for cleanup before
retrying initialization. This is not permission to retry a tool call.

| Budget | Default | Configured maximum |
| --- | ---: | ---: |
| Process sessions |256|4096|
| Sessions per owner / owner-connection |16 /16|256 /256|
| Messages per session lifetime |256|4096|
| Concurrent request response streams per session |4|32|
| SDK channel entries |8|64|
| Standalone GET attempts per session |1|1|
| Initialize request/response |5s|30s|
| Absolute lifetime |15min|60min|
| SDK idle timeout |5min|15min|
| Worker cancellation grace before abort |250ms|5s|

Every budget is finite and nonzero. Absolute lifetime starts at allocation and
also bounds initialization when shorter than the handshake timeout. Counts cover SDK session/channel/cache
ownership, not global process RSS, sockets or HTTP header/response buffering.
The [198 client bounds](mcp-transport.md) remain separate. Application-created
background tasks and output size/work require their own bounds. Share one pool;
creating another independent pool creates another independent budget.

Retirement cancels admission immediately. Transport drop or close hands the
actual worker join to a cleanup owner independent of the request. After grace,
the watchdog may abort that worker, but cleanup continues awaiting the same
join; it never drops the join on timeout. A separate supervisor awaits the
outer initialize/service task. Its close callback only signals retirement,
avoiding self-join. SDK service shutdown preserves response draining, then
aborts and joins its tracked request, notification and send tasks.

Capacity releases exactly once after worker join, service/handler completion
and response stream leases are gone. `Snapshot` distinguishes initializing,
active and closing entries, created/joined workers and services, and releases.
A queued close or removed lookup is not a termination receipt. Unexpected
service-task panic/join failure leaves capacity charged because nested cleanup
is unconfirmed. CPU-blocking/non-yielding application code can prevent finite
cleanup: abort is cooperative at Rust future poll boundaries. Such a session
remains charged; no false completion is reported.

Dropping an unfinished response or standalone GET retires the session. A
completed response does not. The initial HTTP response holds a charged request
stream lease: dropping it before its final initialize event retires the session;
consuming that event completes it without requiring an additional EOF poll.
The initialize response counts toward the lifetime message budget. `wait_retired` only waits; canceling that waiter
does not cancel cleanup. `shutdown` refuses new allocation and waits for owned
cleanup. Restart starts empty; previous IDs cannot recover authority. Submitted
COMMIT/remote work is not rolled back, and completion of independently spawned
application work is not claimed.

## Dependency and validation

The pinned [rmcp3.7.0 adaptation](../../crates/mcp-transport/vendor/README.md)
retains the SDK protocol implementation with four source-file changes and
original hashes/license plus reversible authored patch. Consumer Cargo roots
must use the local patch. No registry/cache edit or dependency version upgrade
is used. The accepted198 client suite is part of regression validation because
service shutdown is shared client/server code.

```sh
python3 crates/mcp-transport/vendor/check.py
cargo test --locked --manifest-path crates/mcp-transport/Cargo.toml -- --test-threads=1
cargo clippy --locked --manifest-path crates/mcp-transport/Cargo.toml --all-targets -- -D warnings
cargo fmt --manifest-path crates/mcp-transport/Cargo.toml --check
```

Committed session regressions exercise refused and concurrent allocation,
changed authority and owner isolation, stalled initialization, canceled close,
worker-before-service completion, handler shutdown, finite message/stream
limits, disconnect, expiry and restart. Exact external S3 receiving-process and
unchanged disconnect evidence is recorded with the delivery checkpoint. Original
research failures remain historical evidence. Isolated prerequisite acceptance
does not itself clear complete G3/native/provider/release gates.

This public source projection preserves the accepted session implementation and
SDK ownership patch. Exact-candidate Rust/process checks, local dependency
resolution and fresh Linux CI remain receiving work; historical acceptance
is not execution evidence for this public tree.
