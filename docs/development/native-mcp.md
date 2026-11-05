# Native MCP daemon boundary (AGENT-202)

The composition root now serves `/mcp/{connection}` with the existing registered
bearer/mTLS identity, current SQLite authority and one process-wide accepted199
session pool. This is N1 lifecycle integration, with **zero tool authority**.
No agent path resolves an upstream credential, observes upstream tools or invokes
a provider. [206A operator preparation](native-tool-review.md) is a separate bounded
operator path; it does not add an agent dispatcher. `tools/list` is empty; `tools/call` returns -32050/tool_not_approved.
Connection grants and account selections are prerequisites for local lifecycle,
never imported tool approvals. Raw HTTP admission and discovery filter protocol.

Public contracts: [operator setup](../user/operator/native-mcp.md),
[agent interface](../user/agent-integration/native-mcp.md), and
[upgrade notes](../user/changes/native-mcp.md).

## Composition and pins

Root Cargo consumes `crates/mcp-transport` and applies its accepted four-file
rmcp ownership patch at the consuming root. Pins remain rmcp3.7.0,
reqwest0.13.2, sse-stream0.2.6, serde_json1.0.149 and Tokio1.50.0.
Existing HTTP reqwest0.12 is separate. Python interoperation uses mcp2.3.0 and
the [28 pinned packages](../../tests/native_process/requirements.txt).
Protocol2025-11-25 is explicit; no stateless2026 or legacy-SSE fallback is enabled.

`src/native/` owns bounded input, exact Origin/Host policy, current scope,
method/ID restrictions, safe error mapping, output caps and lifecycle audit.
The SDK continues to own protocol/session orchestration. Typed pool
Capacity/Limit errors map to429+Retry-After, unavailable sessions to404 and
transport faults to503; arbitrary SDK500s are not mislabeled as capacity.
`src/daemon.rs` cancels native work concurrently with listener drain. TLS
connection tasks are tracked and joined, with bounded handshake/connection close.
The resource observation `native sessions joined` reports only numerical
entry/created/joined/released counters after pool shutdown completes.

Existing198 whole-response outbound bounds are preserved and tested separately.
The original N1 had no reachable daemon outbound hook. 206A operator preparation
now consumes the accepted hook; later dispatch integration must
consume those bounds at the real selected-credential observation/call boundary,
enforce DNS/connected-address and trust policy, and repeat receiving-effect tests.
No protected tool schema is compiled here; later207 retains jsonschema0.60.1
with remote/file retrieval disabled. Adding an unused validator proves nothing.

## Finite policy

Top-level `mcp` config is strict and restart-only. The following defaults are
also the daemon's maximums; they may be lowered but never set to zero:

| Setting | Default / maximum |
| --- | ---: |
| `ingress` |128 concurrent HTTP operations, including authentication/DB/body waits|
| `sessions` |256 process-wide, initializing/active/closing included|
| `sessions_per_agent` |16|
| `sessions_per_connection` |16 per agent/connection|
| `messages` |256 SDK messages and separately256 remembered request IDs|
| `streams` |4 request-response streams per session, plus1 lifetime GET attempt|
| `handshake_ms` |5000|
| `lifetime_ms` |900000 absolute from allocation, including initialization|
| `idle_ms` |300000|
| `request_ms` |10000 total through authentication, input and dispatch|
| `response_ms` |60000 total per response/GET; no heartbeat reset|
| `request_bytes` |262144|

Fixed limits: SDK channel8, cleanup grace250ms, native headers16KiB/64 fields,
JSON nesting32 and8192 structural/string units, output256KiB total/64KiB frame/
1024 frames. Socket-parser allocations and remote/kernel queues are not claimed
by application counters. Notifications/GET/output can consume SDK messages
without consuming IDs. Finite response/GET lifetime can end before session idle
or absolute lifetime; clients must handle that without replay or resume.

Owned worker/service joins and response leases precede capacity release.
Shutdown rejects new ingress, starts pool retirement and closes TLS tasks. The
configured general drain window is a grace period; bounded owned cleanup can
continue afterward (TLS close up to5s, per-task join fallback up to6s before abort
and join). Submitted database/remote effects and independently spawned external
tasks are not rolled back. Incomplete native cleanup returns an error rather
than claiming clean session termination.

`allowed_hosts` and `allowed_origins` are finite lists of at most16 entries.
Host default is loopback. Origin is exact including effective scheme/port;
empty denies present Origin. Both guards are native-scoped. No arbitrary
request `_meta` is admitted: only empty metadata or a bounded standard
`progressToken` is supported for the pinned SDK; no progress capability is added.

## State and migration

Migration0011 adds typed registration protocol/config, non-reused registration
instance identity plus revision, and an agent native-authority epoch. A coherent
joined snapshot covers current agent lifecycle, finite reviewed connection ACL
minus denylist, enabled native row and explicit selection. Full-row runtime
activation must match. Recheck after body/DB waits and in the SDK handler;
failed verified-owner admission retires its scoped sessions. A bounded periodic
sweep also retires invalidated idle sessions. Foreign identity cannot retire a
victim. Normal last-used authentication touches and OAuth token rotations do not
advance authority. Policy/selection changes and any registration revision do.

Protocol/config/destination/egress mutation clears connection ACLs, bootstrap
scopes and selections transactionally. Existing HTTP state/receipts/revocations
are preserved by the migration. 206A adds prepared tool-grant writers/tables; no positive
dispatcher branch exists. Old binaries refuse unknown applied migration0011
before listeners; one database sidecar lock prevents two supported daemon
instances sharing that state. See the public backup/rollback requirements.

Audit `native_lifecycle`/`native_tool_denied` is best-effort (50ms diagnostic
budget), containing operation/agent/connection and no arguments, IDs or auth data.
It is not206's committed tool-admission boundary. The original S3 disconnect
oracle remains separately attributed until real dispatch/admission exists.

## Reproducible checks

Use a disposable worktree and private generated state. No installed service or
real provider credential is needed. Commands:

```sh
cargo test --locked --test native_registration_test --test native_configuration_test
cargo test --locked --test native_lifecycle_test --test native_boundaries_test --test native_state_test --test native_policy_test
uv venv --python 3.13 target/native-python
uv pip install --python target/native-python/bin/python -r tests/native_process/requirements.txt
LOCKSMITH_NATIVE_PYTHON=target/native-python/bin/python cargo test --locked --test native_process_test -- --nocapture --test-threads=1
```

Without `LOCKSMITH_NATIVE_PYTHON`, the Python consumer is skipped explicitly;
Rust/raw/mTLS/process cases still run. A root full-suite count alone does not
establish Python execution. The process target uses ordinary operator CLI,
verified TLS and a separate TCP receiver, including unsupported methods/raw
HTTP zero arrivals, missing/revoked authority, capacity, locking and drain.
Router tests additionally exercise foreign identities and delayed DB/body state.
The ingress pool-wait test holds all database connections and manually polls
requests to prove admission before advancing a paused Tokio clock through the
configured nondefault five-second deadline. A pre-registered timer sentinel services that
boundary, allowing only Tokio's at-most-one-millisecond upward timer rounding;
a missing timeout fails a bounded manual poll rather than waiting for a later
SQLx timer. The clock resumes before connections return and the same
runtime performs real bearer authentication, initialization, ping and deletion
with that same five-second request budget. This also detects a guard that ignores
the configured value and hardcodes the ten-second default. The delayed-body test
uses the ten-second default and reaches its
body barrier with real authentication before pausing; expiry then rejects the
late body without allocating a worker. Neither test relies on a 40ms scheduling
sleep or a 150ms authentication-speed assumption. Production limits are unchanged.

Preserve both accepted public pre-native205a735 binaries before building the candidate.
Set `LOCKSMITH_NATIVE_PRIOR_DAEMON` to that daemon with its matching `locksmith`
sibling, then run the ignored `actual_daemon_native_upgrade_and_prior_binary_refusal`
case in `explicit_binding_smoke_test` with `--ignored --nocapture`.
It creates actual prior state and an applied reviewed receipt, verifies HTTP
X/X/Y before/after/restart, zero native rows, preserved revocations and old-binary
refusal before both listeners. The separate197 prior probe requires its own
pre-0010 binary via `LOCKSMITH_PRIOR_DAEMON`; do not substitute205 for that input.

Required final checks additionally include root locked full suite, both binaries,
strict all-target Clippy/fmt, the separate crate's full locked suite/strict checks,
saved HTTP process smoke, both prior probes, docs/config/help/version and vendor
provenance. Root `--all` does not execute the separate crate's integration tests.
Independent QA builds from public docs before inspecting builder recipes; exact
candidate QA and reviewer verdicts remain separate from builder observations.

## Remaining acceptance

N1 covers actual inbound lifecycle parts of MCP-01/02/05/06, raw-route AUTH-04,
and versioned migration OPS-02 with bounded T04/T09/T12/T13 assertions. It does
not complete useful tool/result/error semantics, protected schemas, committed
authority/audit races or upstream bounds through a reachable daemon hook.
203/206/207/208 retain those assertions and complete two-client/provider/customer
acceptance. G1/G3 remain open; G0/G2/G4 and release/build/recovery/publication gates
are unchanged. Debug/local tests are not optimized/four-platform/live evidence.

SDK payload tracing is suppressed even when `RUST_LOG` enables `rmcp`.
Use the application-owned lifecycle/denial audit and resource diagnostics;
client metadata, request IDs/arguments and cancellation reasons are not logs.
