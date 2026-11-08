# OAuth custody and refresh recovery

AGENT-197 supplies committed incarnation/version identity and stale-write
protection. The local AGENT-205 change extends that same sealed repository with
pre-request uncertainty and owned refresh scopes; no parallel account store is
introduced. See [operator recovery](../user/operator/oauth-recovery.md).

## Stored identity and migration

[0010](../../migrations/0010_oauth_session_incarnations.sql) uses an AUTOINCREMENT
incarnation and nonnegative integer token version. Name/label remains unique.
A committed incarnation is not reused after deletion within that database;
rolled-back inserts may reuse an allocation but return no snapshot. The audit
session display ID is unchanged and is not a CAS key.

[0013](../../migrations/0013_oauth_refresh_uncertainty.sql) adds checked boolean
`refresh_pending`, default0. It preserves existing sealed bytes, nonces, versions,
expiry, scope, account hint, degradation and authority. There is no startup reset.
Old binaries reject unknown migrations before DB-backed listeners. Backup forks,
power loss and cross-host ownership are outside this guarantee.

## Claim, exchange, completion

Local selection and nonempty refresh-token prerequisites are checked first.
`begin_refresh` matches incarnation/name/label/version, requires pending0 and
not degraded, then commits pending1 and increments version. It reserves room for
two increments, refusing exhaustion before network I/O. Decode happens before
COMMIT. Only a committed claim returns the opaque `RefreshAttempt`; its
incarnation/version is the attempt identity.

Network exchange starts after that transaction finishes. No database transaction
spans provider I/O. A failed claim sends nothing. Interrupted, malformed, rejected
or unpersistable exchanges leave pending1; no friendly error write is needed to
maintain refusal. Pending custody is excluded from background selection and
proxy use even when its old access token is still unexpired.

`complete_refresh` seals the full accepted pair and matches that exact attempt
with pending1. Pair, expiry, account hint, pending0, degraded0 and the incremented
version commit together. Decode occurs in that transaction; credentials return
only after COMMIT. There is no name/label-only readback. A canceled caller cannot
assume a submitted SQLite COMMIT was canceled: restart observes either the
complete pair or prior pending state.

Ordinary `update_tokens`, conditional degradation and bootstrap cleanup require
pending0. They cannot clear or delete uncertainty, including using a freshly read
pending row. Explicit operator revoke remains an unconditional current-name/label
deletion; fresh bootstrap creates a new incarnation. Late writers cannot mutate
that replacement. Legacy response/default/scope/identity limitations remain
explicit in the operator guide; this work does not establish provider policy.

## Runtime ownership

The existing per-label locks carry one shared `RefreshOwner`. A mutex serializes
scope registration with closure; a Tokio task tracker owns each admitted future
until it completes or drops. Closure cancels current scopes and refuses new ones.
Proxy resolution, bootstrap create/exchange/cleanup, and each background account
operation run wholly within a scope. Shutdown does not perform delayed cleanup
outside that scope.

The daemon holds its canonical database lock around startup, serving, drain and
OAuth-owner completion. It closes admission on shutdown and on every startup or
runtime return, then waits for scopes before returning. This covers current
OAuth futures even when their HTTP connection task is detached. It does not
claim to join every axum connection task or independently spawned application
work. Arbitrarily dropping the embedding `daemon::run` future is outside the
return guarantee.

Background task spawn is deferred until fallible setup completes. Its retained
handle is joined on normal drain or aborted/joined on forced drain. Shutdown is
selected across an entire tick, including held I/O. Joining Rust futures cannot
roll back already submitted SQL or remote effects; marker/CAS ordering handles
their surviving outcomes.

## Verification boundaries

`oauth_recovery_test` covers claim uniqueness, overflow, stale completion,
conditional cleanup, unrelated writes, owner closure and SQL/write/decode/COMMIT
failures. Deferred foreign-key failures distinguish successful RETURNING from
successful COMMIT. The retained baseline oracle observes two provider sends
before the repair and one after cancellation/reopen.

`oauth::refresh::recovery_process` uses child processes with test-only barriers
inside production custody functions. SIGKILL/reap occurs after committed claim,
after independently observed one-use consumption, after full replacement
seal/decode but before COMMIT, and after COMMIT before return. Reopen retains the
same DB/WAL and receiver; no backup restore or pending reset is used. These are
library worker processes, separately attributed from actual daemon/CLI tests.

The saved daemon tests exercise CLI bootstrap/status/revoke, one-use consumption,
kill/restart, unexpired old-access refusal, fresh reconnect, unchanged authority,
and embedded short-drain return/reacquisition with a late provider response.
The explicit schema12 prior-binary probe verifies exact custody preservation and
refusal before listeners. Root tests, strict Clippy, formatting and binaries are
separate checks. No local result substitutes for consent, provider identity,
live T14, full205 or release acceptance.

## Historical CAS public integration receiving

The earlier public projection preserved the locally accepted OAuth custody source at
`10a0d8b` on public D5 `fa2f4d5`, retaining the intermediate crate version 2.8.0.
Historical local acceptance is not current receiving, CI, provider or release
proof. CAS does not close the consent or ambiguous-refresh/single-owner gaps.

The [CI workflow](../../.github/workflows/ci.yml) explicitly checks out predecessor
`fa2f4d5835a053bf2377e09948d8458017302835` in the runner-only `prior-source`
directory. It checks that commit, builds `locksmithd` with that directory's
`Cargo.toml` and locked dependencies into the existing shared target, and copies
and hashes it under `RUNNER_TEMP/pre-0010-fa2f4d5` before the current suite can
overwrite the target binary. Current compilation remains rooted in the main
checkout. The source commit and preserved daemon SHA-256 are recorded together.

After the ordinary suite, the workflow supplies that copied daemon through
`LOCKSMITH_PRIOR_DAEMON` to the exact
`actual_daemon_oauth_upgrade_and_prior_binary_refusal` test with `--ignored --exact`.
The test requires the explicit binary, creates actual schema-0009 custody,
checks migration preservation and prior refusal before listeners, then restarts
the current daemon. No blanket ignored suite or provider credentials are used;
nonzero build/test results fail CI. Normal lint and formatting gates remain.

The ignored test's local coordinator run and the actual new CI run must each
report their own exact source/binary provenance and result. Neither execution
has been performed by the source-projection builder or reviewer. A normal full
suite alone does not establish this deliberately separate upgrade proof.

## Public refresh-recovery receiving

Refresh recovery ships in 3.0.0 with the existing consuming-root SDK patch.
Historical local acceptance at `3c5f695` is not a current runtime or
live-provider result.

The additional CI probe pins public schema12 source
`4220e62bc381181cf35d4010e95d73adf88f0ea8`, preserves both matching binaries before
current compilation, and supplies the daemon via `LOCKSMITH_RECOVERY_PRIOR_DAEMON`
to `actual_daemon_refresh_upgrade_and_prior_refusal` with `--ignored --exact`.
The three earlier predecessor probes retain their own exact binaries and env.
No ordinary full-suite result implies an ignored probe ran. The old schema12
binary must refuse migration0013 before both listeners, while the new daemon
preserves custody and authority and can restart normally.

## Controlled consent accounts

[Controlled consent](adr-operator-consent.md) extends this repository in migration 0015.
Provider-kind checks exclude those rows from every legacy materializer, refresh
claim/update, bootstrap and status/revoke route; list filters them. A separate
owner-bound attempt CAS governs first publication and absent-account disconnect.
It reuses the AGENT-205 future owner and adds a joined callback-only TLS listener.
That listener binds after the other listeners and before any of them serves, and
stopping before shutdown stops the daemon like any other listener.
No hosted identity, useful read or native OAuth claim follows. Controlled manual
refresh uses the separate owner-bound path in the [consent ADR](adr-operator-consent.md),
with 0016 pending/version CAS, current-match inherited custody and explicit repair.
Legacy kind filters and their background/inline/bootstrap semantics stay unchanged.
