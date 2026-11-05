# OAuth recovery and the 0013 upgrade

Locksmith records an uncertain refresh before contacting the token endpoint.
An interrupted exchange cannot automatically replay its possibly consumed token,
including after a restart. Bootstrap, background refresh and inline proxy
refresh use the same sealed custody. A successful exchange publishes the whole
replacement pair only after its database transaction commits.

For controlled owner-bound consent accounts, use the separate
[consent guide](oauth-consent.md). The commands below manage legacy custody.

## Diagnose and reconnect deliberately

Inspect the explicitly selected registration and label:

```sh
locksmith oauth status "$REGISTRATION" --label "$LABEL"
locksmith oauth list
```

Both status and list include `refresh_pending` and `reconnect_required`.
`refresh_pending: true` means a refresh claim committed without an observed
committed replacement. It can mean an exchange is still in flight; after that
exchange ends unsuccessfully or the daemon restarts, it requires reconnect.
`reconnect_required` is true for pending or degraded custody. The proxy returns
503 `oauth_reconnect_required` for pending custody even if the old access token
has not expired. Background refresh skips it. `/readyz` does not attest every
agent's credential readiness.

A network error, timeout, rejected response, failed persistence or process death
may leave the provider's outcome unknown. The marker is intentionally
conservative: a process can stop after committing it but before sending any
request. Restart never clears it or retries that token. Do not manually clear
`refresh_pending`, edit migration history or repeatedly bootstrap the old token.

Obtain freshly issued credentials through the provider's supported flow. Keep
the refresh token in a permission-restricted file, then run:

```sh
locksmith oauth revoke "$REGISTRATION" --label "$LABEL"
locksmith oauth bootstrap "$REGISTRATION" --label "$LABEL" \
  --refresh-token-stdin < "$PRIVATE_REFRESH_FILE"
locksmith oauth status "$REGISTRATION" --label "$LABEL"
```

Revoke is local and idempotent; it does not revoke the remote provider grant.
A failed bootstrap after an exchange was claimed retains the uncertain row;
revoke must precede a fresh bootstrap. Local revoke can finish while a provider
response is pending. A late response cannot recreate or overwrite the replacement.
Bootstrap and refresh share a per-label lock, so bootstrap may wait for the old
exchange to finish or time out. Already submitted provider actions cannot be
undone by local cancellation or deletion.

Revoke/rebootstrap preserves finite HTTP grants and account selections. Inspect
them before retrying, then make one deliberate call and confirm the receiving
account and audit outcome. A selected label, active registration, successful
bootstrap or `/readyz` alone is not proof of every agent's readiness. See
[account selection](../concepts/per-agent-credentials.md).

## Upgrade and rollback

1. Stop daemons using this state. Keep the previous binaries and configuration.
2. Take a [consistent standalone SQLite snapshot](sealed-state-recovery.md),
   including committed WAL pages through the backup API. Keep matching sealing
   keys separately in their secure store; do not bundle keys into evidence.
3. Start the new binary. Migration 0013 adds `refresh_pending=0` without changing
   existing sealed bytes, versions, metadata, grants or selections. Earlier
   migrations still apply in order;0010 supplies incarnation/version identity.
4. Inspect status and authority, make one intended receiving-account call, then
   restart and repeat. Migration does not repair degraded or unsealable custody.

A binary whose migrations end at0012 refuses the upgraded database before its
DB-backed listeners start. Never bypass that refusal. Rollback requires stopping
the new daemon and restoring the complete pre-upgrade backup with its matching
keys and old binary. Changes since backup are lost, and a restored refresh token
may already have been consumed: obtain fresh credentials instead of replaying it.

One daemon owns the canonical database path. Normal shutdown, forced drain and
startup-error return close OAuth admission and finish owned OAuth scopes before
releasing that lock. This covers current bootstrap, inline and background
callers, not arbitrary filesystem aliases, distributed hosts or an embedding
application forcibly dropping `daemon::run` itself.

## Scope and limits

This is the local custody/recovery part of AGENT-205, building on197's stale-write
protection. It adds neither interactive consent nor verified provider support.
Legacy parsing still preserves an omitted refresh token, retains stored scope,
uses a 3600-second default for omitted expiry and does not validate token type or
provider identity. Those provider/profile policies and consent remain separate
AGENT-204/full205 work. Local checks do not pass live T14, G2 or release gates.
SQLite WAL/NORMAL process-kill recovery is not a power-loss durability claim.
A submitted database COMMIT may finish after caller cancellation: the next read
must observe either the complete committed pair or the durable pending state.

## Reproducible checks

```sh
cargo test --locked --test oauth_incarnation_test --test oauth_recovery_test
cargo test --locked --lib oauth::refresh::recovery_process -- --nocapture
cargo test --locked --test explicit_binding_smoke_test refresh -- --nocapture
LOCKSMITH_RECOVERY_PRIOR_DAEMON=/path/to/schema12/locksmithd \
  cargo test --locked --test explicit_binding_smoke_test \
  actual_daemon_refresh_upgrade_and_prior_refusal -- --ignored --nocapture
```

The prior-binary probe is explicitly ignored by default; the ordinary suite does
not imply it ran. Tests use disposable synthetic state and a separate one-use
receiver, never real provider credentials. Test-only barriers are absent from
shipping binaries. See [custody and evidence boundaries](../../development/oauth-custody.md).
