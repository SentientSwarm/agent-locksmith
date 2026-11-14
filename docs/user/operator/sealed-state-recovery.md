# Recover sealed state and its keys

A SQLite backup alone cannot recover selected accounts. Locksmith uses two
independent AES-256-GCM keys, loaded at daemon startup:

| Environment variable | Encrypted data |
| --- | --- |
| `LOCKSMITH_CREDENTIAL_SEALING_KEY` | Stored credential values in `credential_secrets` |
| `LOCKSMITH_OAUTH_SEALING_KEY` | Access and refresh tokens in `oauth_sessions` |

Each value is base64 encoding of 32 random bytes. Provision each independently
with `openssl rand -base64 32`, redirecting into a new private file under
`umask 077`, or using your deployment's secret store. Do not print keys into
terminal transcripts. Store recovery copies separately from database archives;
record which key version belongs to each backup without recording its value.
Supply the values to the daemon through its environment, not command arguments,
YAML, repository files or diagnostic reports. Never enable shell tracing while
loading them. Locksmith does not manage OS-keychain custody or key escrow.

A missing key permits daemon startup but disables that domain's custody routes.
A well-formed wrong key also permits startup and cannot decrypt existing rows.
`/readyz` is not a key-recovery test. Stored calls fail with 503
`credential_unresolved`; OAuth calls with no key fail with 503
`oauth_sealing_key_unset`, and a wrong key yields 503
`oauth_session_read_failed`. Neither selects another account. The other domain
can remain usable with its own correct key.

## Preserve a consistent recovery set

Stop the source daemon and all other writers using the deployment's normal
shutdown procedure. Freeze configuration and operator changes while collecting
the recovery set. Keep the previous binary and its build identity. Record:

- The configured SQLite path and compatible binary/schema revision.
- Matching YAML, operator credential file, seed policy, TLS certificates/keys,
  trust roots and referenced files. Protect operator hashes and private keys.
- Independent key-store references/versions for both sealing domains, plus any
  selected env or external-secret references. A reference is not a backup of its
  value. Preserve values in their existing secure custody.
- Agent identities, revocations/expiry, finite grants, explicit account
  selections and OAuth labels, and decisions made after the snapshot. Treat
  this inventory as private metadata. Keep audit/operational log files required
  by your retention policy separately; the DB contains only its own log rows.

In a **new private backup directory**, export `DATABASE` as the existing source
DB path and run this block with `sqlite3` installed:

<!-- smoke:sealed-backup -->
```sh
(
  set -eu
  umask 077
  test -f "$DATABASE"
  test ! -e sealed-state.db
  sqlite3 "$DATABASE" ".backup 'sealed-state.db'"
  test "$(sqlite3 sealed-state.db 'PRAGMA integrity_check;')" = ok
)
```

Success has exit 0. A failure leaves the destination untrusted; retain it for
private diagnosis and choose a new directory for a new attempt. This is SQLite's
backup API, including committed WAL pages in one standalone database. It is not
a live-volume tar or a main-file copy. Never discard WAL to make a copy appear
usable, use `immutable` to ignore WAL, or combine files from different snapshots.
The example refuses missing source and existing destination. Only one operator
owns the new directory; the shell checks are not a concurrent backup service.
Protect the snapshot and inventory from later modification and verify their
checksums against your private receipt before recovery.

## Quarantine before restoring traffic

Restore into a new private directory, preserving the original archive and failed
state. Copy the standalone `sealed-state.db` to the new configured database path;
**do not copy old WAL/SHM companions beside it**. Verify `PRAGMA integrity_check`
returns `ok` before launch. Copy matching configuration/operator authentication,
then deliberately change DB/socket/listener/log paths to the isolated recovery
instance. Use only a schema-compatible binary. Do not run a recovered clone
against the same live provider alongside the old instance.

Keep agent ingress closed throughout reconciliation. OAuth background refresh
runs immediately at startup: closing ingress alone does **not** prevent provider
requests. A snapshot's `refresh_pending: false` does not prove its token was not
consumed after that snapshot. Use this existing-command quarantine sequence:

1. Start with `LOCKSMITH_OAUTH_SEALING_KEY` **absent**, not merely replaced by a
   wrong key. Keep both keys absent initially if desired. Use an isolated config
   with no automatic seed import (`LOCKSMITH_SEED_PATH=""`), no unintended legacy
   tools, and the recovered operator file. Preserve the original config for
   review. No OAuth refresh runtime is created without its key.
2. Inventory **every** agent using `locksmith agent list --include-revoked` and
   each agent's `agent credentials list`. Background selection considers bindings
   belonging to revoked agents too. Revoking now removes an agent's bindings, but
   a snapshot taken before that change can still hold them; `locksmith agent
   prune-revoked` removes them. In this release, lookup by a revoked public
   ID can fail: use its unique **name**, first `agent get "$NAME"` and check that
   `public_id` equals the inventory row. Do not skip lookup errors or unmatched
   identities. Record each OAuth registration/label and selection privately.
3. For every OAuth selection, run `locksmith agent unset-credential "$NAME"
   "$REGISTRATION"`. Re-list every agent including revoked ones and verify no
   OAuth selection remains. Stop the recovery daemon. If that complete inventory
   cannot be established, keep it stopped; do not enable its OAuth key.
4. Restart with the compatible keys, still without OAuth selections and still
   closed to agent traffic. `locksmith oauth list` inventories all session labels,
   including unselected ones. Locally revoke **every recovered label** using
   `locksmith oauth revoke "$REGISTRATION" --label "$LABEL"`; confirm absence.
   No selected source remains for background refresh. Reconcile known agent and
   bootstrap revocations, expiry, ACLs and stored-reference changes through normal
   operator commands before restoring any access. An old archive can resurrect
   authority; the database cannot infer decisions made after it was taken.
5. Obtain **freshly issued** provider credentials through its supported flow.
   Bootstrap from a private input file, deliberately restore reviewed selections
   and inspect status. Do not reuse an archived refresh token, even if unexpired.
   See [OAuth recovery](oauth-recovery.md). Local revoke does not revoke the remote
   grant. Keep ingress closed until each intended selected account is verified.

All commands above need your recovery `--socket` and operator authentication as in
[getting started](../getting-started.md). This procedure uses current CLI/admin
entrypoints; it is not an automatic restore command. Isolate outbound networking
as well if other configured sources can contact external services. No local
check establishes that a real provider has accepted a restored token.

A snapshot with `refresh_pending: true` retains the uncertainty marker. Correct
keys do not clear it: it denies even unexpired access and is skipped by background
refresh. Preserve it through recovery; revoke and reconnect deliberately. An
older snapshot without the marker still requires the quarantine sequence above.
Never manually clear markers, edit migration history or retry a possibly consumed
refresh token to see whether it works.

## Verify accounts, then reopen deliberately

Check actual requests with the intended agent credential, its finite grant and
explicit account selection. Verify exact useful response and receiving-account
attribution, not only HTTP readiness. A reference test can use the isolated
[account receiver](../../../examples/http-account-service.py): X and Y must reach
only the selected account; denied/unmapped/revoked callers add zero arrivals.
Inspect safe status/audit output, restart the recovered daemon and verify again.
Do not log decrypted values or send real provider credentials to this fixture.
Reopen traffic only after the recorded reconciliation is complete.

Changing an upstream stored value is supported: `agent set-credential "$AGENT"
"$REGISTRATION" --stored-bearer-stdin < "$PRIVATE_VALUE_FILE"` creates a fresh
reference. Intentionally shared agents need deliberate selection of that new
reference; other agents selecting the old live reference are not silently moved.
This is value replacement, **not sealing-key rotation**.

To rotate the stored sealing key, re-key the database offline. Stop the daemon
and take a SQLite-safe backup first; the daemon reads stored values per request.
Put each base64 key in its own owner-only file (mode 0600 or 0400):

```bash
locksmith rekey-credentials --database "$DB" \
  --old-key-file "$OLD_KEY_FILE" --new-key-file "$NEW_KEY_FILE"
# {"rekeyed":N}
```

Every `credential_secrets` row, tombstoned rows included, is resealed under the
new key with a fresh nonce in one transaction. If the old key cannot open any
row, the command exits 1 and changes nothing. A key file that group or others can
read is refused with exit 2. Keys are never taken from arguments or the
environment, and no value is printed. Then start the daemon with
`LOCKSMITH_CREDENTIAL_SEALING_KEY` set to the new key. Backups taken before the
re-key still need the old key; keep it according to your security policy.

Changing only the configured key without re-keying strands existing ciphertexts.

OAuth key replacement likewise does not re-encrypt old rows. Use quarantine,
local revocation and fresh provider issuance under the new key, then explicit
selection and receiver verification. Losing the old key is not decryptable
recovery; fresh provisioning is a different operation.

## What the local proof covers

`cargo test --locked --test explicit_binding_smoke_test sealed_restore -- --nocapture`
uses actual disposable CLI/daemon processes and separate synthetic token/API
receivers. It executes the snapshot block above, restores distinct directories,
checks both key domains, authority and sealed-row preservation, restart,
revocation reconciliation and an actual pending-refresh snapshot. Receiver
counters distinguish arrivals from one-use token consumption. No owner state or
external provider is used; this is not power-loss or remote-backup durability.

This supplies AGENT-136's local key recovery proof and a SQLite snapshot primitive
for AGENT-175. Layer8's configured-volume discovery, template/env forwarding,
packaged backup/restore commands, private-site rehearsal and upgrade automation
remain separate work. It does not establish full AGENT-175, packaged AGENT-213,
live OAuth compatibility or release acceptance.

## Controlled consent custody

Migration 0015 controlled accounts remain unbound and are excluded from legacy
refresh. Pending attempts expire on restart; committed custody survives. This
does not relax the no-OAuth-key quarantine for restored legacy rows, including
revoked owners. Follow [controlled consent](oauth-consent.md) for owner-bound
status/disconnect and the explicit older-binary refusal cost.
