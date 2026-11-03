# Selected-source isolation (AGENT-177)

D1.2 extends the accepted D1.1 admission boundary at `2c91942`. It reuses the
existing binding repository, sealed stores, op cache, OAuth sessions and
registration/label refresh locks. It adds no account model or source backend.

## Behavior

Stored header/bearer bindings resolve only their selected reference. Missing,
tombstoned, unreadable, wrongly sealed and empty values fail with 503 and no
upstream operation. Op header/bearer bindings use only the selected cached value;
empty/failed/missing entries fail with 503. Requests never run op commands. Op
failures record a classified cause rather than dependency output.

Both OAuth variants require an explicit nonempty session label and usable client
and token endpoint metadata. `default` is valid only when selected literally.
Operator writes reject malformed choices; already persisted malformed selections
fail closed. The selected OAuth mechanism and refresh endpoint survive template
auth-kind and endpoint changes. The CLI's explicit `--oauth-session` command
snapshots registration metadata instead of persisting empty placeholders.

Missing, revoked, degraded, unreadable or empty selected sessions fail with 503,
without another label/account. Empty refresh responses cannot replace stored
tokens. Concurrent expired requests retain the selected label and existing lock.
Provider response bodies do not enter errors or logs.

Background refresh uses explicit binding metadata before unsealing a session.
Unselected sessions and conflicting selections are skipped; disabled registrations
retain their existing inactive behavior. Operator bootstrap retains its explicit
initial exchange. This does not introduce session provenance or revision fencing.

Credentialed config.tools/M0/shared-bearer requests without a real agent identity
return 401 before resolution or dispatch. Startup avoids resolving these legacy
credentials without the admin substrate. Readiness diagnoses the missing agent
authenticator and explains registration/authentication/selection. Credential-free
admission retains the current policy. Direct file-backed bindings remain
unsupported; startup explains the owner-driven stored-snapshot mapping. The
D1.1 real-daemon file snapshot import remains covered.

## Proof

Real application/authentication, SQLite and sealing are used. Only external
upstreams/token endpoints and the op command are synthetic. New source-isolation
modules extend existing feature fixtures rather than replace injection, refresh,
account-header, filtering or CLI assertions. Legacy positive proxy/discovery and
optional cloud fixtures now use an actual registered agent and explicit sealed
selections; no production migration is implied by this test setup.

- `tests/source_isolation/stored.rs`: both shapes, healthy alternates, every
  custody failure, zero operations and reference-only reads.
- `tests/source_isolation/op.rs` and `tests/op_source_safety_test.rs`: selected
  cached values, failures, separate command/operation counts and safe logs.
- `tests/source_isolation/oauth*.rs`: both mechanisms, labels, cross-kind and
  endpoint edits, missing/degraded/revoked/unsealable/empty sessions, safe refresh
  rejection, six concurrent calls producing one exchange, background selection,
  and actual CLI metadata snapshots.
- `src/oauth/refresh/selection_tests.rs`: unselected, shared-consistent and
  conflicting background selections through real repositories.
- `tests/identityless_isolation_test.rs`: M0 and shared-bearer 401, security audit,
  zero operations and actionable readiness.

The baseline regression build used `CARGO_TARGET_DIR=target/agent177-baseline`
against accepted production source at `2c91942`. Candidate artifacts use the
worktree's ordinary target directory. No shared target or dependency symlinks
are used. The baseline run had nine regression failures across four targets
and one already-correct OAuth case; the failures establish dispatch, label,
mechanism, endpoint and unseal-status gaps.

## Delivery boundary

This is the local AGENT-177 slice. Reviewed migration (AGENT-178), operator
cutover/release acceptance (AGENT-179), real provider checks and D4 grant/cache
findings remain separate. No installed daemon operation, production mapping,
publication, version or changelog change is part of this work.

## Verification receipt

Local Darwin arm64, Rust/Cargo 1.94.0, accepted base `2c91942`:

- `CARGO_TARGET_DIR=target/agent177-baseline env -u OPENAI_API_KEY -u
  ANTHROPIC_API_KEY cargo test --test phase_f_oauth_proxy_test --test
  credential_store_proxy_test --test op_credential_proxy_test --test
  identityless_isolation_test isolation --no-fail-fast`: exit 101, nine
  intended baseline failures and one pass across four targets.
- `env -u OPENAI_API_KEY -u ANTHROPIC_API_KEY cargo test --all --no-fail-fast`:
  exit 0, 597 reported passes, zero failures/ignored cases across 84 targets.
  Two optional live-cloud tests return early without keys; no provider coverage
  is claimed.

Intermediate failures are retained in the local evidence: CLI test setup used a
positional name before correction; a refresh-signature/fixture compile mismatch
occurred during edits; the first complete run exposed the legacy discovery
fixture. The corrected fixture retains all filtering/redaction assertions with
actual agent authentication. A deliberate op-log red test demonstrated dependency
output disclosure before its classified-error fix. No assertion, timeout or
provider requirement was weakened to pass these checks.

Final serial checks on the same candidate source:

- `cargo test --test credential_store_proxy_test --test op_credential_proxy_test
  --test phase_f_oauth_proxy_test --test identityless_isolation_test --test
  discovery_test`: exit 0, 35 passes. These rerun the final audit and caller-auth
  assertions after the complete suite.
- `cargo build --bins`: exit 0 (debug binaries).
- `cargo clippy --all-targets -- -D warnings`: exit 0.
- `cargo fmt --check` and `git diff --check`: exit 0 each.
- `env -u LOCKSMITH_LOCAL_PROOF_MISSING
  LOCKSMITH_LOCAL_PROOF_SELECTED=proof-selected LOCKSMITH_LOCAL_PROOF_EMPTY=
  cargo run --example local_risk_proofs`: exit 1, 21/23 observations match.
  Exactly the two existing D4 findings remain: unrestricted legacy ACL growth
  and a disabled database row with a stale active snapshot. This diagnostic is
  not a conformance pass.

## QA corrections after `6e51cf5`

Independent QA reproduced two in-scope gaps despite the 597 passing committed
checks: F1 allowed inline requests to use conflicting shared-session metadata,
and F2 treated the API's 409 `wrong_kind` as fatal during CLI kind discovery.
The earlier green receipt does not override those counterexamples.

F1 now shares the background consistency check with inline admission, under the
existing registration/label lock and before any session unseal, cached-token use
or refresh exchange. Every binding for that session must agree with the admitted
selection. Unavailable or conflicting metadata returns a safe 503. Consistent
sharing remains supported; no provenance or revision schema was added.

F2 skips only the structurally classified `wrong_kind` envelope on a 409, as well
as existing 404s. Other conflicts and failures still propagate. The actual CLI
and private-daemon test now covers model/tool/infra for both OAuth mechanisms.

`tests/source_isolation/oauth_consistency.rs` retains QA's actual auth/SQLite
probes and adds cached-token denial plus consistent cached/expired controls for
both mechanisms. Baseline production at `6e51cf5` with physically separate target
artifacts fails four regressions (three OAuth assertions and the CLI matrix),
with 28 passes. The expired conflicts send X's refresh token to Y and dispatch;
the cached conflict dispatches without an exchange. Fixed targeted suites pass
32 cases: every conflicting cached/expired case is 503 with X/Y/operation counts
0/0/0; consistent controls preserve X and expected exchange counts. Errors,
audits and captured logs do not disclose token sentinels.

Follow-up verification on the corrected candidate tree, same local runtime:

- `env -u OPENAI_API_KEY -u ANTHROPIC_API_KEY cargo test --all --no-fail-fast`:
  exit 0, 603 reported passes, zero failures/ignored. Two optional live-cloud
  cases return early without keys; no live-provider coverage is claimed.
- `env -u OPENAI_API_KEY -u ANTHROPIC_API_KEY cargo test --test
  phase_f_oauth_proxy_test --test cli_e2e_test -- --nocapture`: exit 0, 32 passes.
  The CLI matrix exercises all six kind/mechanism combinations, and full CLI
  unit coverage preserves unrelated/malformed conflict responses.
- `cargo build --bins`, `cargo clippy --all-targets -- -D warnings`,
  `cargo fmt --check`, and `git diff --check`: exit 0 each, run serially.
- The same synthetic `cargo run --example local_risk_proofs` invocation above:
  exit 1, 21/23 matching and exactly the two existing D4 findings. No conformance
  pass or release acceptance is claimed.
