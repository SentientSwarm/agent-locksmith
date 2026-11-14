# Explicit HTTP grants and activation (3.0.0)

An operator can configure an ordinary HTTP tool/model, grant a named agent,
select its account and verify attribution at the receiving service. Start with
[the runnable local setup](../getting-started.md); it includes a Python reference
API and a separate customer-service configuration example.

## Authority and lifecycle

New agents and bootstrap tokens default to **no HTTP grants**. Choose a finite
allowlist of existing enabled tool/model names. A selected account alone does
not grant access; an allowlist alone does not select an account. Both are needed,
including an explicit `None` selection for an authless service. Denylist wins.
Unsupported method/resource/operation selectors are rejected. These grants cover
the entire connection; they do not provide finer operation authorization.

Registration names identify routes within their lifetime. Deleting a name or
changing upstream/egress removes its grants and per-agent selections atomically,
including pending reviewed bootstrap scopes. Recreating that name requires
explicit destination review, grants and selections again. Disable/re-enable
preserves existing choices. `tool delete` on a seeded entry is a disable;
operator-created entries are hard-deleted. Changing a credential template does not repoint an
agent's selected account. Binding writes require a current enabled HTTP target.

Enrollment, own-token rotation, expiry and revocation remain available. Rotation
preserves identity, policy, expiry and selections while invalidating the old
secret at the next authentication. Agent credentials cannot administer another
agent or choose arbitrary source references.

## Upgrade existing agents

Follow [the offline migration guide](../concepts/migrating-account-bindings.md).
Schema migration marks historical policies unreviewed, so old callers are denied
until deliberate review. `preview --grants` proposes finite current eligibility
for restricted and formerly unrestricted agents. Unknown and future names are
excluded. Review grants and account references; apply commits both atomically.
All-preserved bindings and empty grant sets can be reviewed with zero inserts.
An unchanged repeat is safe; later policy, destination, account or lifecycle
changes make the old plan conflict. Old unreviewed bootstrap tokens must be
re-minted. Account-only migration does not review grants.

Plans contain references, not values, and cannot establish credential readiness.
Use a compatible current binary/schema for recovery and reconcile any restored
revocations. Do not restore old implicit authority or delete migration receipts
to replay a stale plan.

## Runtime state and repair

New admissions use one current SQLite snapshot of agent lifecycle/policy,
registration and selected account. The persisted registration must match active
runtime configuration. A DB-backed missing/disabled/pending entry cannot fall
through to legacy YAML. Selected-source failures never retry another account,
a registration default or an unauthenticated request.

An admin write can be saved while activation fails: HTTP 503
`connection_activation_failed`, `saved: true`, CLI exit 1. Read the saved entry,
repair the cause, then repeat the intended write or restart normally. That route
remains denied; unrelated healthy connections can still serve. Operator reads
report `active`, `pending` or `disabled`. Public discovery and personalized
`/skill` include only current allowed active entries. Config-only discovery
reports `configuration_only`; it cannot claim persisted activation.

`credential_readiness: not_checked` and `/readyz` are deliberate limits.
An active route or selected reference is not proof its credential/provider
works. Verify receiving-account identity with a benign real request. Use
[audit and denial repair](../operator/account-binding-troubleshooting.md).
Revocation, clear, grant removal and disable affect the next admission;
already-admitted work may finish. There is no new stream cancellation system.

## Local verification

```sh
cargo test --locked --test explicit_binding_smoke_test -- --nocapture
cargo test --locked --test catalog_suite -- http_grants_test:: http_activation_test::
```

The [saved process smoke](../../development/explicit-account-bindings-smoke.md)
executes lifecycle, reference X/X/Y, independent customer header/path, denial
repair, restricted/unrestricted/empty migration, future-entry denial, activation
failure/restart and next-admission revocation. Receiving counters distinguish
zero dispatch from an upstream rejection. Synthetic local services do not
establish live provider, Kamiwaza or installed-deployment compatibility.
The two baseline D4 failures in the older diagnostic are historical findings;
they are not the acceptance oracle for this change.
