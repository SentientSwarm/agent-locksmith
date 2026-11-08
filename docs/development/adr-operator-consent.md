# Controlled consent and durable custody

The bounded AGENT-204 increment adapts the shipping daemon and CLI using the
existing OAuth sealing key, account table and AGENT-205 operation owner. It accepts only
an explicit loopback HTTPS `controlled-linear-v1` profile. Fixture identity is
not hosted provider acceptance and `connected_unbound` confers no agent authority.

Migration 0015 extends oauth_sessions with a checked kind and owner/profile/identity
metadata. Legacy typed records retain required refresh tokens. Controlled records
preserve optional refresh/expiry without sentinels; legacy get/list/claim/update/
bootstrap/revoke reject or exclude them. Existing native account support stays
None/StoredBearer. A previously selected absent label cannot bypass this boundary.

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
