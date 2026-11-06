# Controlled consent and durable custody

The bounded AGENT-204 increment adapts the shipping daemon and CLI using the
existing OAuth sealing key, account table and AGENT-205 operation owner. It accepts only
an explicit loopback HTTPS `controlled-linear-v1` profile. Fixture identity is
not hosted provider acceptance and `connected_unbound` confers no agent authority.

Migration 0015 extends oauth_sessions with a checked kind and owner/profile/identity
metadata. Legacy typed records retain required refresh tokens. Controlled records
preserve optional refresh/expiry without sentinels; legacy get/list/claim/update/
bootstrap/revoke reject or exclude them. At that increment native account support
remained None/StoredBearer. The later [controlled native selection](../user/operator/native-oauth.md) adds explicit owner delegation; a previously selected absent legacy label still cannot bypass it.

One attempt table holds a state hash and sealed verifier/quarantine. Claim commits
before code exchange. Final publication rechecks the attempt/run/deadline and
registration instance/revision inside one transaction, decodes inserted custody
before COMMIT, and returns only after COMMIT. Lifecycle triggers invalidate first
INSERT attempts across registration and legacy account ABA. An absent-account
status revision includes its active attempt; owner-checked If-Match disconnect
can cancel first publication. Cancel after commit leaves durable custody intact.

The outer daemon owner retains the callback supervisor across later startup
failures. The callback listener owns and joins every new connection task; the
existing OAuth owner cancels complete callback futures before state-lock release.
This does not claim joining unrelated axum connection tasks. Submitted SQL/remote
effects can remain uncertain after cancellation and require status reconciliation.

The migration preserves sqlite_sequence highwater, including all-deleted tables.
Older binaries refuse the new schema/config; no transparent downgrade is promised.
The [operator guide](../user/operator/oauth-consent.md) owns the exact limits,
commands, disclosure policy and controlled-only compatibility costs.

## Manual controlled refresh

The controlled refresh increment reuses the same table and AGENT-205 RefreshOwner. Migration 0016
permits refresh_pending for controlled rows without widening legacy kind guards.
An opaque claim exists only after an observed pending/version COMMIT; pending
cannot be reconstructed as a runnable claim. No DB transaction spans network I/O.
Completion matches owner/incarnation/version/profile and the captured current
registration, decodes complete returned custody and observes COMMIT before success.
The versioned account revision includes pending/version/current source metadata.

Custody inherited from migration 0015 lacks creation-time registration provenance. Fresh owner
status may deliberately authorize the current exact profile match after identical
recreation; stale status/claim cannot follow a later instance or revision. No
backfill from a possibly evicted attempt is treated as provenance. Missing expiry
and scope remain unknown; omitted refresh retains only the claimed old secret.
The existing identity wire accepts a narrow consent-or-refresh guard, with both
schemas and IDs verified and old/new exact-secret screening. No new account store,
scheduler, authority or hosted provider policy is introduced.

Checked committed output is retained outside cleanup/timeout. Pending and
submitted-COMMIT uncertainty reconcile through status and explicit disconnect/new
consent. Library worker barriers, shipping daemon death and embedded owner return
are distinct effects; process-kill/WAL is not power-loss durability.
