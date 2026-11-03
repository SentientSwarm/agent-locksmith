# Explicit HTTP grants: cutover and acceptance contract

This contract covers finite HTTP grants, migration, coherent admission and
activation, plus the process journey and [consumer entry point](../user/getting-started.md).
It narrows the conceptual [integration boundaries](http-integration-boundaries.md)
to the existing HTTP proxy, local operator/agent identity and D1 account selection.
The original implementation was accepted locally at `ad0025a`; this public
projection starts from D1 `ce6491d1`. Historical local acceptance is separate from
receiving tests, remote integration, formal review, release and publication of
this projection. This document states the technical contract, not a new verdict.

## Existing identity foundation

The saved actual-process test is:

```sh
cargo test --locked --test explicit_binding_smoke_test actual_daemon_agent_token_lifecycle -- --nocapture
```

It launches disposable `locksmithd` and `locksmith` processes, uses CLI operator
issuance and bootstrap minting, enrolls through the real admin UDS endpoint, and
observes a local receiving service. A consumed single-use bootstrap token cannot
enroll another usable agent. Agent rotation requires that agent's current token
and secret, replaces the hash, preserves identity, ACL, binding and expiry, and
invalidates the old secret on the next authentication. A different agent's
secret cannot rotate the caller. An agent token cannot list agents, revoke
another agent or change its source reference through operator endpoints.

Expiry is an absolute Unix timestamp on the agent record; rotation does not
extend it. The original authentication check rejects timestamps earlier than
the current second. HTTP admission and bootstrap consumption now require an
expiry strictly in the future, rejecting equality too.
The operator API can set expiry; the bootstrap token's expiry limits enrollment,
not the enrolled agent's lifetime. Operator revocation denies subsequent
authentication. Expired and revoked requests produce zero receiving operations.
No lifecycle implementation change was needed for these demonstrated behaviors.

## Smallest connection and authority model

- A registration name is the stable HTTP route identity within its lifetime.
  Its upstream/egress configuration describes the approved destination. Reuse
  the existing tool/model admin and CLI paths, not a parallel connection API.
- A grant is a finite agent allowlist, minus denylist, **and** that agent's
  explicit D1 `(agent_id, registration)` account selection. A selection is a
  complete env/stored/op/OAuth reference or explicit `None`; it never inherits
  the registration template. Only the operator chooses sources and grants.
- Missing/null allowlists confer no HTTP authority. Existing policies must be
  reviewed before cutover, including restricted lists containing unknown names.
  A small per-agent reviewed-policy marker distinguishes legacy policy from a
  finite approved policy; it is neither activation nor credential readiness.
  New operator/bootstrap policies validate current target names. No entry gains
  access merely by being added later, whether credentialed or authless.
- Authority is connection-wide ordinary HTTP. No method, operation or resource
  subset is enforced. Supported registration, grant, bootstrap and binding
  payloads reject unsupported selector fields rather than ignoring them.
- Deleting a registration removes its bindings and grants in the same database
  transaction. Recreating the name starts without that authority. Setting a
  binding on an unknown target is rejected. Replacing upstream/egress requires
  deliberate reapproval; old bindings must not become valid at the new endpoint.
  Seed/repository paths obey the same lifecycle rules. Disable/re-enable retains
  identity and selections; disabled targets deny admission until explicitly enabled.
- An operator binding replacement is explicit account reapproval. Token refresh
  within that selected OAuth account is not a grant or destination change.

## Reviewed migration and recovery

Extend D1's offline reference-only preview/apply/snapshot/receipt implementation.
The owner reviews each agent's finite current eligible registrations and existing
account references; restricted and formerly unrestricted agents use the same
transaction. Exclude disabled, unknown/future and denied entries. Preserve
reviewed existing selections, including agents with all bindings already present,
and support an explicit empty grant set. Do not require inventing a new account
binding just to review policy. Preserve denylist, expiry and revocation.

Apply validates reference and authority drift, writes finite policy plus its
review marker atomically, and records a receipt. An unchanged repeat is a no-op.
Reapplying after revoke, destination or selection drift must conflict; never
restore an old grant from a prior plan. Keep D1 account-migration compatibility
explicit. Preview does not retrieve credentials or establish provider readiness.

Stop the daemon for offline cutover and back up compatible binary, schema,
configuration and state. An old binary does not enforce the new policy contract.
Recovery uses current authoritative state and preserves current revocations;
blind snapshot rollback is not an authorized recovery mechanism. No automatic
rollback or credential fallback is added.

## Admission and truthful activation

Read the current agent policy/lifecycle, registration and explicit binding in
one coherent SQLite read snapshot. This prevents combining an old endpoint with
a newly selected account across concurrent owner writes. Compare the persisted
registration with the runtime catalog's full row, not its second-resolution
timestamp. The successful authoritative decision is the admission boundary.
Credential resolution and HTTP work follow that boundary; already admitted
requests/streams may finish under existing deadlines. There is no immediate
stream cancellation claim or new cancellation subsystem.

Committed revocation, disable, destination/account/grant changes govern later
admissions. A DB-backed absent, disabled or stale entry cannot fall through to a
same-name legacy YAML route. Missing/unavailable binding, source or OAuth state
fails closed, with no default/alternate/unauthenticated retry.

An admin write that persists but fails runtime activation reports saved plus
pending/failed activation, never unqualified active success. The affected entry
denies new admission; unrelated matching healthy entries remain usable. Operator
read surfaces and discovery use the same freshness predicate. Active runtime
configuration does not attest credential readiness. `/readyz` remains an instance
dependency check, not proof that every selected account works. Preserve D1's safe
missing-binding diagnosis and deliberate operator repair guidance.

## Acceptance sequence

1. Lifecycle proof: actual lifecycle proof above and the two saved diagnostic failures.
   The [diagnostic environment recipe](http-grants-baseline-diagnostics.md#reproduce-against-the-real-application)
   (`LOCKSMITH_LOCAL_PROOF_SELECTED=proof-selected`, `LOCKSMITH_LOCAL_PROOF_EMPTY`
   empty, `LOCKSMITH_LOCAL_PROOF_MISSING` unset) plus
   `cargo run --locked --example local_risk_proofs` at the accepted baseline
   reports 21/23 safe contracts and exits 1: unrestricted growth and persisted
   disable with stale catalog. These are historical findings, not acceptance.
2. Finite authority: finite policy, strict authority inputs, lifecycle cleanup and
   reviewed migration. Verify all-preserved/empty/restricted/unrestricted plans,
   drift/repeat, preserved source references, no future grants or resurrection.
3. Coherent admission: coherent authoritative admission and activation reporting, including
   fault injection, unrelated healthy requests, restart/recovery and concurrent
   owner changes. Verify zero upstream arrivals for denied admissions.
4. Consumer acceptance: saved actual CLI/daemon reference and independently configured
   customer-service smoke, account attribution, full checks and independent
   consumer execution using shipped setup/migration/troubleshooting and actual
   generic/personalized `/skill` and catalogs. Exercise denial, operator repair,
   retry and cleanup. Reviewer and QA evaluate the exact final revision.

Tests use temporary state and synthetic local accounts. None establishes live
provider or Kamiwaza compatibility. Record revision, environment, command, exit
and sanitized observations per [project completion](../development/project-completion.md).
