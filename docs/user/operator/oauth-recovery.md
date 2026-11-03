# OAuth recovery and the 0010 upgrade

This repair prevents a late token exchange from replacing a deleted/recreated
account, degrading its replacement, or returning credentials whose database
write did not commit. It applies to manual bootstrap, background refresh and
inline proxy refresh. It does not add interactive consent or provider support.

## Disconnect and reconnect deliberately

Use the explicitly selected registration and label. These operator commands
use your configured admin socket and operator credential:

```sh
locksmith oauth status "$REGISTRATION" --label "$LABEL"
locksmith oauth revoke "$REGISTRATION" --label "$LABEL"
locksmith oauth bootstrap "$REGISTRATION" --label "$LABEL" \
  --refresh-token-stdin < "$PRIVATE_REFRESH_FILE"
locksmith oauth status "$REGISTRATION" --label "$LABEL"
```

Obtain the new refresh token through the provider's own supported flow and keep
its file permission-restricted. Do not paste it into logs, shell arguments or
review material. Revoke is local and idempotent; it does not revoke the remote
provider grant. Revoke must precede bootstrap when a local session already exists.

Local revoke can complete while an exchange is waiting on the provider. A late
response cannot restore the deleted row. Bootstrap and refresh still share a
per-label lock, so a new bootstrap can wait for the old exchange to finish or
reach its timeout. This ordering is why the historical repository overwrite is
not claimed as a demonstrated CLI replacement exploit.

A stale or failed persistence result makes bootstrap fail or proxy return 503;
there is no alternate account/default fallback. Failure cleanup and degradation
also require the original incarnation/version. A newer committed token pair or
replacement survives those old failure paths. Previously admitted requests may
finish; this change cannot undo a request already received by the provider.

OAuth revoke/rebootstrap leaves the agent's explicit finite HTTP grant and
account selection intact. Inspect both before retrying, then make one deliberate
call and confirm the receiving account and audit outcome. A selected label,
active registration, successful bootstrap or `/readyz` is not proof that every
agent's source is ready. See [account selection](../concepts/per-agent-credentials.md).

## Upgrade and rollback

1. Stop every daemon using the state directory. Do not run old and new writers
   against the same database. Keep the previous binaries and configuration.
2. Make a verified backup of the stopped SQLite database (including its WAL if
   one remains). Keep the matching sealing keys in their existing secure store;
   never bundle them into source, diagnostics or a release artifact.
3. Start the new binary with that configuration. Migration 0010 rebuilds
   `oauth_sessions`, preserving sealed token bytes, nonces, expiry, scope,
   degradation, account ID and timestamps. Each existing row receives a new
   incarnation at version zero. Grants and bindings are unchanged.
4. Check status, explicit authority and one intended receiving-account effect.
   Restart and repeat the intended call. A missing/unsealable/degraded source
   remains unavailable; migration does not grant trust or repair credentials.

Old binaries whose embedded migrations end at 0009 refuse a database containing
0010 before the DB-backed agent/admin listeners start. Do not delete migration
history or disable the guard. To roll back, stop the new daemon and restore the
complete pre-upgrade backup with its matching keys and old binary. Changes since
that backup will be lost. Restored rotating refresh tokens may already have been
consumed: reconnect through the provider instead of blindly replaying them.

## Remaining rotation limit

This fix does **not** make rotating refresh crash-safe. A provider may consume a
refresh token before a network failure, process loss or failed custody commit.
The current implementation has no durable pre-request uncertainty marker and
cannot prove that replay after restart is safe. If the outcome is uncertain,
stop using that session, revoke locally and obtain a fresh provider grant.
Separate durable-refresh work must provide the durable marker, complete pair commit, explicit
`reconnect_required` state, no replay after ambiguity and single active state
owner. Consent remains separate work. G2 remains blocked by those requirements and live
provider proof; this local CAS fix does not pass that gate.

## Reproducible checks

Run the normal locked suite and the saved process smoke. The upgrade probe needs
an explicit pre-0010 binary built in its own checkout:

```sh
cargo test --locked --test oauth_incarnation_test
cargo test --locked --test explicit_binding_smoke_test \
  actual_daemon_oauth_revoke_during_exchange -- --nocapture
LOCKSMITH_PRIOR_DAEMON=/path/to/pre-0010/locksmithd \
  cargo test --locked --test explicit_binding_smoke_test \
  actual_daemon_oauth_upgrade_and_prior_binary_refusal -- --ignored --nocapture
```

The last test is deliberately ignored by default because a prior binary cannot
be inferred from the current checkout. Report its separate result; the normal
suite does not imply it ran. Fixtures use synthetic tokens and disposable local
state, no real provider account. See the [custody contract](../../development/oauth-custody.md).
