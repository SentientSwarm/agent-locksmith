# Explicit account bindings — unversioned D1 change notes

This change requires deliberate account selection for every authenticated
agent/registration pair. It is a compatibility change, not a published release
or authorization to upgrade an installed deployment.

## Operator-visible behavior

- A registered bearer or mTLS agent needs its current ACL and an explicit
  binding. Agents A/B may share X; C may select Y. The registration template
  describes an option, not an inherited grant. New agents/entries get no binding.
- No selection: 403 `tool_not_allowed`. Clearing a valid selection has that same
  effect on the next admission. Replacing it changes only future admissions.
- Unavailable/corrupt selection or missing/empty selected env: 503
  `credential_unresolved`, zero upstream operations. Stored/op/OAuth failures
  have their corresponding safe 503 class; another healthy source is not tried.
- Missing/wrong/revoked caller: 401 `invalid_credential`. Credentialed identityless
  legacy routes: 401 `agent_identity_required`; enable actual registered-agent
  authentication rather than inventing a privileged compatibility identity.
- An explicit no-auth selection is different from a missing source. It still
  obeys agent authentication and ACLs; caller Authorization/API-key headers are
  stripped. Authless identityless routes retain the pre-existing admission policy.
- OAuth selections capture client/endpoints/mechanism plus a literal nonempty
  label, including `default`. Consistent selections can share one account/session.
  Old empty placeholders require deliberate re-selection. Conflicting bindings
  for a shared session deny cached-token use and refresh; no endpoint retry.

## Upgrade

Stop the deployment's writers, retain credential/key custody and take a
WAL-safe SQLite backup. Follow [reviewed migration](../concepts/migrating-account-bindings.md):
preview reference metadata, select only intended proposals and apply atomically.
Existing explicit selections remain untouched. Repeating an unchanged plan
inserts zero rows; later clear/edit or relevant drift requires fresh review.
Receipts are bookkeeping, never runtime authority.

Prefixed env, legacy strings, direct file sources, conflicting/unknown references
and identityless paths need owner mapping. Preview never reads/imports secret
values or verifies provider availability. Preserve header prefixes deliberately
when selecting a replacement source; verify the receiving account before traffic.

## Reproduce the local cutover

```sh
cargo build --bins
cargo test --test explicit_binding_smoke_test -- --nocapture
```

This executes actual disposable daemon/CLI setup and upgrade commands, X/X/Y,
clear/broken/repair/revoke/template/noauth checks, stopped-daemon backup and
migration, actual process restart and cleanup. See the
[smoke evidence contract](../../development/explicit-account-bindings-smoke.md),
[getting started](../getting-started.md) and
[troubleshooting](../operator/account-binding-troubleshooting.md).

Local synthetic upstreams establish account isolation, not compatibility with
live providers, Kamiwaza, remote deployments or provider grant policies. Existing
focused tests cover env/header/bearer, stored, op and both OAuth mechanisms. Four
optional provider tests can return early without their endpoints/credentials;
reported passes are not provider coverage. At the D1 baseline, the local
diagnostic recorded two later D4 findings: legacy unrestricted ACL growth and
disabled-row stale catalog activation. Those are historical probes;
[explicit HTTP grants](explicit-http-grants.md) defines their replacement
contract and saved verification. Active-stream cancellation and pool replay/egress
policy remain outside this change. Final acceptance belongs to the lead after independent
QA/review of the delivered candidate; these notes alone do not claim acceptance.

## AGENT-180 shipped guidance follow-up

The rendered generic/personalized `/skill` now distinguishes missing account
binding from actual ACL denial. It directs the operator to inspect audit reasons
and safe `agent credentials list` references before deliberate `set-credential`
repair. Catalog lists show ACL eligibility, not binding existence or source health.
Selected-source 503 guidance covers environment, stored, 1Password and OAuth
without alternate-account/default/unauthenticated retries. OAuth bootstrap alone
does not authorize proxy use; explicitly select a nonempty label including
literal `default` when intended. Current architecture, wire/error/identity,
skill-reference and client examples describe that boundary.

The saved smoke additionally fetches both rendered forms and executes their
personalized diagnosis/repair commands against its disposable daemon, observes
account X and confirms clear denies again. Prior D1 acceptance and failure/recovery
evidence remain historical. This follow-up was accepted locally in D1; remote
integration, version tags and publication are tracked separately.
