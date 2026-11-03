# OAuth custody write contract

This change updates the existing sealed `oauth_sessions` repository, with no second
credential cache or new dependency. See [operator recovery and upgrade](../user/operator/oauth-recovery.md)
for the user-visible ordering and limitations.

## Persistence identity

Migration [0010](../../migrations/0010_oauth_session_incarnations.sql) uses an
`INTEGER PRIMARY KEY AUTOINCREMENT` incarnation and a nonnegative integer
`token_version`. `(name, session_label)` remains unique. A committed incarnation
is never reused after deletion within that database, including immediate
same-label/same-timestamp recreation and restart. Rolled-back inserts can reuse
an allocation, but no snapshot escapes before commit. Database restoration is a
stopped-state operation; this is not an identity guarantee across backup forks.
The existing timestamp-based audit display ID is unchanged and is not a CAS key.

Create seals tokens, inserts a fresh incarnation and materializes the inserted
row inside a transaction; it returns only after commit. Duplicate labels still
require explicit revoke first. Existing rows migrate at token version zero with
all sealed bytes and metadata unchanged. No grant or binding migration is needed.

## Exchanges and failures

Every exchange carries its original `OauthSession` snapshot. Update predicates
incarnation, name, label and token version, increments version and uses
`RETURNING`. The unique incarnation permits at most one result; no result is a
typed stale conflict. The version cannot overflow or become a SQLite real.

The access token, optional rotated refresh token, expiry, account ID, degraded
flag and timestamp commit together. An omitted rotated refresh token preserves
the matched stored refresh ciphertext and nonce. Decode happens inside the same
transaction; the materialized row returns only after successful commit. There is
no post-commit name/label-only readback and no use of provider plaintext after a
failed write, decode or commit. Ordinary already-admitted work may finish after
that commit; this is not remote rollback.

Failure degradation is conditional on the same incarnation/version and advances
the version. Bootstrap cleanup deletes only its own unchanged snapshot. Both
reject zero-row results. Operational degradation events are emitted only after
successful persistence. Neither path may affect a replacement or newer pair.
Explicit operator revoke remains an idempotent current-name/label deletion and
invalidates pending snapshots immediately.

Bootstrap, background refresh and inline refresh retain the shared per-label
network lock. Revoke deliberately does not wait for that lock. No SQLite write
transaction is held over network I/O. Source selection/consensus, finite grants,
sealing, activation and no-fallback admission behavior remain unchanged.
Repository errors never authorize fallback; public write failures and runtime
logs do not include provider bodies or token material.

## Verification and boundaries

`oauth_incarnation_test` preserves the three failing-before assertions and adds
concurrent-writer, version, conditional cleanup, same-timestamp/restart, exact
sealed migration and database failure checks. A deferred foreign-key constraint
makes COMMIT fail after UPDATE RETURNING, so a passing statement cannot be
mistaken for committed custody. A corrupted refresh ciphertext similarly checks
that failed materialization rolls the new access token back.

The saved process tests use real CLI/admin/daemon operations, a controlled token
endpoint and a receiving HTTP service in the separate test process. Four cases
hold bootstrap/inline refresh responses, revoke, then release success/failure;
old-account receiver effects must stay zero. Deliberate replacement and restart
must work while grants and selections remain unchanged. The separately invoked
prior-binary probe creates real 0009 state, upgrades it, checks preservation and
verifies SQLx's unknown-migration refusal before listeners. It does not establish
safe simultaneous old/new writers.

No interactive consent route is claimed: manual bootstrap is the available
analogue. Provider token semantics, refresh uncertainty after process loss and
single-state-directory ownership remain separate consent and durable-refresh/state-ownership work. CAS alone
does not establish crash-safe rotating refresh, provider eligibility, G2 or
3.0.0 release readiness. No version bump or publication accompanies this fix.

## Public integration receiving

This public projection preserves the locally accepted OAuth custody source at
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
