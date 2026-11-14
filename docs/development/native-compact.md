# Bounded native compact facade (AGENT-210)

Base: the stage B native dispatcher. The facade is an opt-in projection and
reference protocol over existing native authority and dispatch. It adds no
upstream client, credential mechanism, grant store, observation service, vendor
patch or migration. [Public contract](../user/agent-integration/compact-mcp.md).
Full AGENT-208/AGENT-210 and provider acceptance, and AGENT-211 model
evaluation, remain open.

## Composition

`registrations::McpConfig.compact` defaults false and is omitted when false.
The ordinary route remains. `native::Context` stores immutable facade identity;
`scope::select` compares it before any use/ready transition or close. The pool
Scope remains owner/connection/authority, so compact cannot multiply quotas.
Existing ingress/Host/Origin/identity/ID/body/deadline/drop/join rules apply.

First compact list uses the same Context scope guard and Pins source/name/digest
capture, including empty. A separate Context registry holds up to 32 random
128-bit hex handles and 32 continuation records. Search never marks described.
The strict wrapper grammar belongs to the facade and does not relax reviewed
schema validation. The current coherent `effective::Snapshot` is re-read under
the existing owned Control. Search/describe do not materialize secrets or make
network calls; invoke returns an ordinary `dispatch::Invocation` and reaches
`Runtime::dispatch` once. It retains original agent/connection/source/actual name,
full immutable digest and public arguments. All merge, secret screening, DNS/TLS,
final authority/audit COMMIT, result validation and unknown-outcome semantics are
shared with standard MCP.

Registry work takes pins then registry mutex, with no await under either. A
provisional clone is rendered, encoded and checked against Control and time-based
freshness while that same registry lock remains held. Only success replaces it.
Concurrent search/describe cannot erase another receipt. Output failure/capacity
refusal/cancellation before publication commits no state. Later response loss
retires the session; it does not undo published state or submitted remote work.
The server receipt proves checked rendering, not peer comprehension or delivery.

Cursors bind exact original query bytes, effective limit, offset, current
observation generation, grant revision and ordered eligible names/digests.
Handles are session-local and require current matching Source/pin/digest plus a
separate full-described digest. They preserve existing exact-regrant/unchanged-tool
semantics, even when a cursor becomes stale. `Approved.effect` is copied only from
a validated immutable review and includes `mixed`. Complete schema and result
encoding are bounded; individual standard-valid tools can exceed compact limits.

Safe refusal diagnostics use the existing fixed vocabulary and outcome path.
Queries, handles/cursors, schemas, protected values and arguments are not logged.
Search/describe create no `mcp_admitted` row. Invoke audit identifies the actual
upstream tool, never merely the facade `invoke`. Outcome diagnostics remain
best-effort and submitted COMMIT/effect uncertainty is not rollback or replay permission.

## Compatibility and checks

A pre-compact CLI reads the new JSON through the new daemon.
A pre-compact daemon starts on omitted metadata but fails startup with stored
`compact:true`, before any HTTP listener becomes available. Reupgrade starts;
configuration toggle has cleared authority, so explicit connection selection,
observation, review and grant repair is required. No transparent downgrade or
narrow route-only 404 claim is made. Configure compact before authority setup.

Run in a disposable authorized checkout and existing target with the repository's
locked toolchain/dependencies and generated local TLS fixtures:

```sh
cargo test --locked --offline --all -- --test-threads=1
cargo clippy --locked --offline --all-targets --all-features -- -D warnings
cargo fmt --check
cargo build --locked --offline --bins
cargo test --locked --offline --test native_compact_process_test -- --nocapture
LOCKSMITH_NATIVE_PYTHON=/path/to/existing/pinned/python \
  cargo test --locked --offline --test daemon_suite native_compact_sdk_test:: -- --nocapture
QA_RECEIVER="$PWD/tests/native_dispatch/receiver.py" \
  cargo test --locked --offline --features s3-disconnect-proof \
  --test native_compact_ownership_test --test native_dispatch_ownership_test \
  -- --nocapture --test-threads=1
LOCKSMITH_COMPACT_PRIOR_CLI=/path/to/pre-compact/locksmith \
LOCKSMITH_COMPACT_PRIOR_DAEMON=/path/to/pre-compact/locksmithd \
  cargo test --locked --offline --test native_compact_process_test \
  actual_prior_opt_in -- --ignored --nocapture
```

The two pinned SDKs exercise standard/compact X/shared-X after rotation/Y/None,
fixed and all-protected inputs, with receiving-time exact admission witnesses.
Focused tests cover atomic registries, empty pins, query bytes, stale/foreign
references, schema-before-invoke, current authority, quoted names, oversized
schema/signature/escaped envelope, cross-facade methods and shared capacity.
Actual INSERT/deferred-COMMIT failures require zero admissions and receiver effects.
The byte-identical historical S3 disconnect assertion is included twice through
separately attributed production setup/wire glue: compact glue performs full
search/describe before translating the original read call to invoke. It uses the
real production slots, DB wait, session retirement and joins. No research executor
is used. The original deadline test remains separately standard-attributed.

These commands are reproducible checks, not claims of a new run. Model
token/latency improvements are unmeasured.
