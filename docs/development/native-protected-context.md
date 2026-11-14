# Fixed native context and phase diagnostics (AGENT-207)

This extends accepted manual native dispatch through the existing review,
Source, grant-CAS, session-pin and committed dispatcher paths. See the
[operator contract](../user/operator/native-context.md) and
[agent interface](../user/agent-integration/native-mcp.md). No new policy store,
provider adapter, background logger, dependency or migration is introduced.

## Immutable contract and one captured call

Review accepts an optional plain `context` object. Empty/omitted values keep
`{tool,context:{},effect,retry:"never"}` exactly as before. Nonempty values add
`context_profile:"fixed-top-level-v1"` in the existing canonical digest domain.
Unknown profiles refuse. The complete observed tool remains stored and matched
against the current observed digest; it is never replaced by the projection.

`native_authority/protected` validates fixed whole values with the existing
finite schema/value evaluator. It removes only protected top-level properties
and required entries to derive the public tool. Presence checks precede public
argument validation, injection and full original-schema validation. Aggregate
limits apply after merge. The captured merged object follows the existing
single dispatch path, with no later context lookup or alternate submission.
Before INSERT, the serialized full contract passes the exact duplicate-safe
native JSON reader used by grant/effective loading. Its32-depth/8192-unit budget
applies to the combined observed tool and context, not just the authoring input.
An unreadable combined contract returns `review_limit` without changing reviews
or grants; a smaller valid contract remains usable.

Nonempty review materializes current custody without network before acquiring
the final write transaction. That transaction rechecks current Source and
observation; credential references are immutable in supported rotation paths.
Known-secret screening happens before persistence/response. Empty reviews keep
their previous custody requirements. Dispatch materializes again and screens the
full merged object before DNS. Same-reference ciphertext mutation is a separately
labeled database-tamper test, not a supported rotation mechanism.

Review candidates do not activate grants. Existing source/generation/revision
CAS chooses an exact digest. Changed contracts cannot enter old pins; unrelated
unchanged tools retain authority. The existing final admission transaction
rechecks current authority and time after audit INSERT and before COMMIT.
All source, DNS/TLS, transport, schema, slot, ownership and no-replay boundaries
from [stage B](native-dispatch.md) remain.

## Phase evidence and cancellation

Each dispatch creates a random server operation ID and an owned `Trace`.
Unapproved names are not copied into diagnostics. After approval, safe tool,
digest and Source attribution are captured; arguments/context never are.

| Last observed phase | Terminal record / meaning |
|---|---|
| `not_admitted` | `native_tool_denied`, controlled refusal before COMMIT submission; `not_submitted` |
| `commit_submitted` | `native_tool_unknown`, COMMIT confirmation absent; `unknown`, never assumed rollback |
| `admitted` | `mcp_outcome`, confirmed admission but no tool send started; `not_submitted` |
| `submitted` | `mcp_outcome`, call submitted but no checked result; `unknown` |
| `completed` | `mcp_outcome`, checked `success` or `tool_error` |

Mandatory `mcp_admitted` still commits through the caller-owned transaction
before one TOOL send. A submitted COMMIT may finish after cancellation; a remote
effect may outlive its future. Missing terminal evidence remains unknown.
Static reason codes cover argument/authority/custody/preparation/DB/cancellation
paths; unrecognized internal codes collapse to `request_refused`.

Normal diagnostics use the remaining original deadline, capped at50ms, inside
the existing owner/slot. Forced owner loss or capacity refusal can leave only a
static `native_operation_interrupted` marker. There is no detached completion or
promise of a terminal row for every operation. Checked result state remains
outside cleanup and diagnostic cancellation boundaries, so those failures do
not overwrite an available result. Cancellation that drops the whole handler
can prevent response delivery; it does not turn missing evidence into success.

The new status-returning audit mirror distinguishes `Absent`, `Written` and
`Unavailable`. Losing the file handle remains unavailable on subsequent calls.
Raw I/O errors and paths are replaced with static sink diagnostics. Existing
HTTP/legacy callers still use best-effort wrappers. Mutex/DB waits are ordinary
cancellable async waits. The sink performs synchronous filesystem operations:
an async deadline cannot interrupt an arbitrary blocked syscall. No hard50ms
filesystem bound, fsync durability, complete history or recursive audit is claimed.

`diagnostics` in operator snapshots is a current local-state explanation.
Credential readiness stays `not_checked`; provider readiness stays `unverified`.
Activation errors still use existing static refusals. No status read fetches
provider state or claims a saved review is an effective grant/session pin.

## Compatibility and verification

Actual preserved accepted d7 binaries establish schema14 compatibility. The
probe starts on genuine prior state, upgrades, refreshes observations after
every restart, checks empty/context/mixed grants and old input refusal, revokes
while downgraded, then re-upgrades. Old B refuses the entire context-bearing
intersection; this availability cost is intentional. It can still use empty
contracts and explicitly revoke. Exact stored bytes/digests survive; no grants
are resurrected. No schema marker is needed for the observed fail-closed path.

Focused commands:

```sh
cargo test --locked --test native_suite native_context_test::
cargo test --locked --test daemon_suite native_context_process_test:: -- --nocapture
LOCKSMITH_CONTEXT_PRIOR_DAEMON=/path/to/preserved/d7/locksmithd \
  cargo test --locked --test native_context_process_test upgrade -- --ignored --nocapture
```

The upgrade probe holds only while the current schema is 14 (through commit
`4b777cb`). After migration 0015 the prior binary refuses the upgraded database;
the consent upgrade probe covers that refusal.

The new separate TLS receiver checks merged values against the immutable review
and reads the committed admission/digest before each effect. Actual daemon/CLI
journeys cover X/shared-X/Y/None, projection, override refusal, candidate versus
grant/pin transitions, selected-secret refusal, missing custody, labeled tamper,
INSERT/deferred-COMMIT failures and checked-result/cleanup/diagnostic failures.
Sink tests distinguish absent, written, failed/fileless and held-mutex states.
Retain the original B/S3 source and run its production adapters separately;
new context fixtures do not relabel the old empty-context assertions.

Final gates remain locked root full suite, all-target/all-feature strict Clippy,
fmt and both binaries; separate transport suite/Clippy/fmt/vendor checks; saved
HTTP/native/definition/preparation/dispatch/OAuth/SDK and actual prior probes.
The pinned Python environment must be set so SDK cases do not silently skip.
Independent QA constructs new public-only Python/Rust calls before these recipes;
reviewer runs selected independent checks after QA releases execution.

Development before/after logs and setup mistakes are distinct from exact-final
and independent evidence. This ships in 3.0.0; full206/207/208, hosted
providers/customer UAT and compact/model gates remain open.
