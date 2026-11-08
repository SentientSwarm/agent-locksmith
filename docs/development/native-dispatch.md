# Reviewed native dispatch (AGENT-206B)

Manual native None/live StoredBearer accounts support a bounded useful call.
[Controlled OAuth](../user/operator/native-oauth.md) reuses this dispatcher with
owner-stamped, token-version/trust-bound authority and access-only custody.
[Operator observation and grant](../user/operator/native-tool-review.md) and the
[ordinary agent interface](../user/agent-integration/native-mcp.md) describe setup.
The original None/StoredBearer increment built on A preparation without a new
migration or dependency. Controlled OAuth adds migration 0017 and the repair costs
in its guide. Supported local customer pins now reach this same dispatcher through
[dedicated definition activation](../user/operator/integration-definitions.md),
with schema 18 and separate ACL/account/tool-authority repair. Hosted provider
acceptance, dynamic context and full AGENT-206 acceptance remain separate. [Compact MCP](../user/agent-integration/compact-mcp.md)
uses this same dispatcher. [Fixed context and phase diagnostics](native-protected-context.md)
extend this path under bounded207. This ships in 3.0.0.

## One current dispatcher

`native/tools` carries the original outer ingress deadline through the SDK's
existing HTTP Parts extension, together with request/session cancellation.
`native_authority/effective` reads current source/activation/lifecycle, then joins
finite grants to exact account-key/name/digest reviews and the fresh current
observation. It never uses connection permission as tool permission. The first
successful session list locks its Source and exact contract map, including empty;
concurrent lists cannot replace it. Later lists intersect those pins with current
state. Calls before list refuse, as do newly introduced names/digests.
Before installing any pin, the effective snapshot's instance/revision/epoch
must match the original session scope. A transition after the earlier lifecycle
check cancels the session instead of attaching a new source to it.

`native_authority/dispatch` is the only positive submission path. It validates
arguments against the pinned contract before materialization or upstream I/O,
then approves/pins DNS and initializes a fresh bounded upstream connection.
No SQL transaction spans that preparation. `dispatch_audit` rechecks captured
source, generation and grant revision in a short transaction, inserts through
the existing AuditRepository, rechecks after INSERT waits and commits. Only a
successful COMMIT permits one tool call. It checks cancellation, original
deadline, expiry and observation freshness again before submission.

An already-submitted COMMIT may finish after cancellation. A submitted tool can
have remote effects after local cancellation. Neither implies rollback. There
is no retry, alternate credential, replay or result-driven fallback. A deliberate
new request can duplicate an uncertain effect. This is not exactly-once execution.

One existing205 owner and eight shared slots cover observation and dispatch,
including preparation, DB waits, validation and finite cleanup. The deadline is
min(original ingress deadline,10s from dispatch); it does not reset after early
SSE headers, body input or each phase. DELETE cleanup is attempted within the
same owned lifetime; helper acceptance of405 is not remote deletion proof.
No new detached tasks or SDK worker are introduced by dispatch.

## Values, output and diagnostics

The [finite A schema grammar](native-tool-review.md) is evaluated without a new
schema engine or external retrieval. Object arguments are limited to32KiB,
16 levels and4096 visited values. Unicode scalar lengths, closed objects,
required fields, array limits and exact parsed-number comparison apply.
Integer values require i64/u64 JSON representation; integral floats are refused
for integer fields. Numeric enum/const comparison does not round large integers
through f64; this is not arbitrary-precision arithmetic.

Raw duplicate-safe JSON/SSE validation runs before SDK normalization. Supported
call output is at most32KiB: up to16 text blocks of16KiB each, optional object
structuredContent and boolean isError. Successful output schemas require matching
structured content; valid tool errors preserve isError. Other content, metadata,
links/resources/tasks and secret-bearing output are refused as unknown outcome
if already submitted. Known selected-secret screening visits decoded keys and
strings; no general DLP claim. No output causes automatic retrieval or replay.

`mcp_admitted` is the committed safe audit record with server-generated random
admission ID, agent, connection, tool, digest and source attribution.
`mcp_outcome`/JSONL mirror are best-effort after commit. Ordinary async waits
use at most50ms within the operation deadline; synchronous filesystem calls
are not preemptible. See the fixed-context diagnostic contract for phases and
checked-result preservation. Missing outcome means unknown. Raw arguments, upstream
payloads, credentials and RPC/session IDs are absent. Existing SDK trace filtering
still applies under explicit rmcp tracing. HTTP audit writes keep their original
pool-insert then best-effort mirror behavior.

## Verification and historical attribution

The root full suite, strict all-target Clippy/fmt/binaries and separate transport
suite/Clippy/fmt/vendor checks remain required. Focused targets:

```sh
cargo test --locked --test native_dispatch_test
cargo test --locked --test native_dispatch_process_test -- --nocapture
```

Install the [pinned Python environment](../../tests/native_process/requirements.txt)
and set `LOCKSMITH_NATIVE_PYTHON` to its interpreter for both SDK consumers.
Without that variable the Python branch explicitly reports NOT RUN; the final
acceptance matrix must set it. The positive process journey uses generated TLS,
actual daemon/CLI, X/X/Y plus None, separate receiver effects and committed-audit
observations. INSERT and actual deferred-COMMIT errors each yield zero tool
arrivals. Result refusal after an effect produces exactly one arrival, no retry.

Original S3 `disconnect_wait.rs` is retained byte-for-byte at SHA256
`fccaf7ac289db9ec899988c91742d2deb8ed8b412d10308dbc2781f6349943b7`.
Its unchanged source/function is an intentional size-policy exception to preserve
that external oracle. The opt-in test target avoids silently requiring its
historical environment input in ordinary tests:

```sh
QA_RECEIVER="$PWD/tests/native_dispatch/receiver.py" \
  cargo test --locked --features s3-disconnect-proof \
  --test native_dispatch_ownership_test -- --nocapture
```

Separately hashed adapters in `tests/native_dispatch/glue/` expose the production
router, real authority runtime/slots and actual DB pool. The preparation barrier
holds the disposable upstream initialize response. The one-session closed
observer watches actual manager retirement/join completion, not a substitute
cancellation trigger. The original assertion holds every real pool connection,
drops the HTTP response and observes retirement before releasing the pool;
admissions and TOOL arrivals remain zero. A separate real-daemon case drops the
response during held preparation. The same target checks delayed body input
followed by a final pool wait against the original ingress deadline.

The accepted A public consumer/empty-list assertions remain historical A
attribution. Compatible in-tree A operator smoke now expects the granted list
and refuses an unapproved tool instead; this is an explicit B adaptation.
New B consumers and original S3 adapters have separate source hashes. Early
builder setup/compile and unsuccessful SQLite-lock observer probes are retained
as development evidence, not passing disconnect proofs. Independent final QA
constructs its own new public-doc consumer before reading these test recipes.

## Upgrade and release limits

There is no B schema migration: schema14 state, account bytes and finite grants
remain readable by accepted A. A cannot execute native tools. Every restart
requires fresh observation; downgrade/re-upgrade never grants new authority.
Preserve accepted0a binaries before building and run the ignored compatibility
probe with `LOCKSMITH_DISPATCH_PRIOR_DAEMON`. That probe holds only while the
current schema is 14 (through commit `4b777cb`); after migration 0015 the A binary
refuses the upgraded database, which the consent upgrade probe covers. Earlier schema13/12/11 refusal
probes retain their own exact prior binaries and attribution.

Actual local checks are not hosted provider, optimized/four-platform, release or
broader G0–G4 acceptance. The operator's manual credential selection is distinct
from external OAuth consent and independently proven provider identity.
