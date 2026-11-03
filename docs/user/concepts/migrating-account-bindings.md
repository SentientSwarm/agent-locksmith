# Upgrade to finite HTTP grants and explicit accounts

`locksmith migrate-bindings` is an **offline owner tool** for an existing,
current-schema SQLite database. It uses filesystem access as authority and does
not use an operator token or contact the admin listener. Run it on the daemon's
host with the daemon stopped for cutover. It does not stop services for you.
Rehearse on a disposable SQLite backup with synthetic credentials first.

The `--grants` workflow freezes current eligible HTTP routes into a reviewed finite
allowlist and explicit account selections in one transaction. It never creates
agents, imports files, copies credential values or supplies runtime fallback.
Existing agents are marked unreviewed by schema migration and cannot call HTTP
connections until reviewed. Old bootstrap tokens must be re-minted with current
finite grants; they cannot enroll under inherited unrestricted scopes. Existing explicit selections are preserved, including broken
ones. Unmapped credentialed callers remain denied.

## Back up a consistent database

Stop your deployment's daemon through its normal operator procedure. Prevent
other processes from changing registrations, agents, ACLs, credentials or the
legacy configuration until verification finishes. Preserve the configuration and
required credential/sealing-key custody separately using your normal secure
backup procedure; the plan does not contain them.

Use SQLite's backup API or a tool using it. For example, in a private working
directory with `sqlite3` installed, export `DATABASE` as the existing database
path and run from that directory:

<!-- smoke:backup -->
```sh
umask 077
test -f "$DATABASE"
sqlite3 "$DATABASE" ".backup 'before-bindings.db'"
sqlite3 before-bindings.db 'PRAGMA integrity_check;'
```

Expect `ok`. The existing-file check avoids accidental new databases. A normal
SQLite connection permits WAL coordination files when stopped writers have
removed them; some SQLite CLI builds cannot do that with `-readonly`. No
application writes are issued by this backup. **Do not copy only `.db` with WAL.** Committed
rows can still reside in `-wal`. SQLite's backup API includes committed WAL
contents in a consistent standalone backup. Keep the backup private: unlike the
reference-only plan, it contains authentication hashes and sealed credentials.
Never move a partial `.db`/`-wal`/`-shm` set into a running deployment. Do not use
SQLite `immutable` mode to ignore a possibly live WAL.

Preview uses a read-only SQLite connection and one consistent read transaction;
it does not create/migrate databases, change journal mode or write application
rows. SQLite may use its normal WAL reader coordination files. Apply uses one
`BEGIN IMMEDIATE` transaction, including all drift checks and writes. The tool
requires the existing schema; upgrade schema through the normal deployment
procedure separately if it reports `migration_database`. The new daemon applies
embedded migrations on startup; the offline CLI does not. After the backup,
keep agent traffic closed, start the new compatible daemon with the deployment's
configuration/custody, confirm schema startup completes, then stop it before
preview/apply. Historical agents are denied during this interval. Rehearse this
sequence on a copy first; do not point the rehearsal at the live database.
Keep the pre-schema backup separate from any later cutover backup.

## Preview, review and select

Set `LOCKSMITH_BIN` to the delivered CLI binary and `CONFIG` to the stopped
deployment's configuration path. Keep `DATABASE` from the backup step.

<!-- smoke:preview -->
```sh
umask 077
"$LOCKSMITH_BIN" migrate-bindings preview --grants \
  --database "$DATABASE" \
  --legacy-config "$CONFIG" > bindings-plan.json
cp bindings-plan.json bindings-reviewed.json
```

`--legacy-config` is optional on both commands. Supply the same configuration on
preview and apply. Without it, the plan explicitly says config-only paths were
not inventoried. YAML records tool names, safe header/env references and source shapes, alongside
unsupported-file/identityless reasons. A single legacy `${VAR}` name can be
inventoried without its surrounding literal. Expressions are never expanded;
paths, prefix literals and inline values are neither resolved nor exported.
No config entry is imported. Keep configuration writers stopped during apply;
its reference inventory is read and checked inside the SQLite write transaction.

Review the JSON's agent IDs/names, allowlists/denylists, registration names/kinds,
source references and reasons. Deny wins and an empty allowlist denies everything.
Only historical unreviewed rows with absent lists treat current entries as eligible
for this offline proposal. Live missing/null lists grant nothing. Restricted
unknown names and future entries are excluded. Review destination registration
configuration separately before accepting its reference.

Change **only** `selected: false` to `selected: true` on desired entries whose
`action` is `propose`. Also mark each reviewed agent in `grants` as selected.
The grant list is finite, includes no unknown names, and can be empty. You may
select only grant rows when all bindings are already preserved or no entry is
eligible. Select at least one grant or binding proposal. Leave `preserve` and `skip` entries,
all source metadata, inventory, snapshot and format fields unchanged. The tool
rejects other edits. To select a different source, repair/reselect it through the
existing operator commands and generate a fresh preview; do not hand-edit the
proposed AuthSpec. It does not guess an account from a partial legacy selection.
Regenerate and review plans made with an older tool that omitted legacy metadata.

For a supplied same-name legacy tool, automatic mapping requires a known exact
wire form: no-auth, or an unprefixed typed env header matching the registration.
Nonempty prefixes (including `Bearer `), legacy strings, file/unknown shapes,
duplicates and conflicting references require owner mapping. A startup-derived
Header can lose a legacy prefix; it must not be selected automatically. Literal
prefix/string contents are not fingerprinted as secret values. Unsupported routes
stay unmapped; safe reference/shape edits invalidate reviewed plans. Existing
explicit choices remain preserved, and unrelated mappings remain selectable.

Plan files contain sensitive reference metadata (agent/public IDs, ACLs, env
names, 1Password paths, stored handles and public OAuth client/endpoints/scopes).
Keep them private and out of version control. Their digests cover reference
metadata, **not credential values or token hashes**. Preview/apply do not read
environment credential values, unseal blobs, execute `op`, or exchange tokens.
They cannot attest that an env/op value, sealing key or provider account works.

## Apply and verify

<!-- smoke:apply -->
```sh
"$LOCKSMITH_BIN" migrate-bindings apply \
  --database "$DATABASE" \
  --legacy-config "$CONFIG" --plan bindings-reviewed.json
```

First output is `{"inserted":N}` for the selected proposals. An unchanged repeat
prints `{"inserted":0}`. This count covers newly inserted bindings, so a successful
review-only or empty-grant cutover also prints zero. Selected finite allowlists,
reviewed-policy markers, binding rows and a narrow receipt/revision in existing
`registrations_meta` commit together. Seed-version and unrelated metadata are
untouched. These bookkeeping entries have no proxy/runtime authority.

Relevant inventory changes produce exit **5**, `migration_conflict`, with no
partial writes. Checks include registration destination/auth/lifecycle, agent
identity/status/ACLs, explicit references, stored-reference lifecycle, OAuth
session metadata and migration revision. Checks compare contents as well as
lifecycle timestamps, so same-second ACL/reference edits are detected. The
comparison is conservative: unrelated inventory additions can also require a
new preview. Expiry is checked again at apply time, including repeat.

A receipt pins the exact reviewed subset and resulting metadata state. A later
explicit edit or clear makes the old plan stale: reapply cannot overwrite or
recreate that binding. Missing/corrupt receipts also fail closed when the
revision/post-state no longer matches. Never delete migration receipts or the
revision to retry an old plan. Generate and review a fresh plan instead.

Invalid inputs exit **2** (`migration_invalid`); database/schema/permission or
write failures exit **1** (`migration_database`). Errors omit SQL and source
contents. A failed insertion, including a failed receipt write, rolls back all
grants, bindings and bookkeeping.

Start your deployment normally. Use existing
[`agent credentials list` / `set-credential`](../cli-reference.md) commands and
real authenticated agent requests to verify receiving-account attribution. Check
that two intentionally shared callers reach X and a distinct caller reaches Y;
unmapped callers must return 403 with zero upstream requests. Broken selected
sources must return 503 without trying another account. Changing a template
must not repoint migrated rows. New registrations/accounts require new finite grants and explicit
reviewed selections; this tool installs no automatic mapping job.

Without `--grants`, preview retains the older account-only format. Applying that
format does not review an old agent policy; run the finite grant cutover before
expecting HTTP access.

The migration regression command is `cargo test --test binding_migration_test`.

It runs actual offline CLI processes against disposable SQLite fixtures and
checks real registered-agent authentication/custody/forwarding against synthetic
receiving upstreams after reopening the database. The project-level [saved smoke](../../development/explicit-account-bindings-smoke.md)
executes the marked backup, preview and apply commands here with a stopped
disposable daemon, then starts a new process and checks X/X/Y. Run it with
`cargo test --test explicit_binding_smoke_test -- --nocapture`. Neither target
proves compatibility with live providers.

## Remediate unresolved cases

- `env_value_unverified`, `op_value_unverified`, `sealed_value_unverified` and
  `oauth_session_metadata_only` describe metadata evidence, not healthy values.
  Verify custody and account attribution through normal authenticated calls.
- Missing/tombstoned stored sources or missing/degraded OAuth sessions require
  deliberate operator repair. Preview never reads blobs or repairs credentials.
- Conflicting OAuth client/endpoint selections for the same registration/session
  require owner reconciliation. Migration uses the same full-metadata consensus
  as inline/background refresh; it never chooses the first binding. Malformed
  selection metadata must also be repaired before OAuth proposals are usable.
- Complete registration OAuth templates with a known inherited `default` session
  can produce an explicitly labelled proposal. Missing sessions are skipped;
  other labels are never substituted. Existing missing-label/incomplete OAuth
  placeholders are preserved and flagged for deliberate re-selection, never
  reconstructed from an edited template.
- Revoked/expired agents, ACL denials and disabled registrations are skipped.
  Existing explicit rows stay preserved even when unusable. Repair policy through
  normal operator management only if intended, then preview again.
- Unsupported file/config-only/identityless paths need owner mapping. Register
  and authenticate an actual agent using the
  [existing identity workflow](agent-identity-and-acl.md), establish the intended
  registration and supported source, and explicitly select it. There is no
  synthetic privileged agent or automatic file-to-stored credential import.
  For transformed legacy env sources, deliberately select the intended supported
  per-agent mechanism/source using `set-credential`; no runtime prefix support
  is added by this tool.

## Roll back safely

A failed apply leaves the pre-apply state intact. After a successful apply,
prefer deliberately clearing/replacing individual selections through normal
operator commands. Clearing denies subsequent access; it never restores a
registration default.

For recovery, use a binary compatible with the current migrated schema and
explicit-grant enforcement. Never roll back to a binary that ignores the reviewed
marker or restores implicit grants. For a full state restore, stop all writers
and restore the complete consistent backup
using your deployment's SQLite-safe restore procedure, including its matching
configuration and custody requirements. Preserve the failed/current database
securely for diagnosis. Restoring an old database can also restore revoked
identities, old ACLs or old selections: reconcile those decisions before restart.
Restoring the pre-migration database under explicit-selection enforcement leaves
unmapped callers denied. Do not roll back to implicit-account runtime fallback.
