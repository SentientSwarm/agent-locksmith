# D1: Explicit account bindings

Status: Historical D1 technical contract, implemented in the accepted local
D1 source at `1fab249`. Local acceptance does not establish remote integration,
a version tag or publication. See the [change guide](../user/changes/explicit-account-bindings.md)
and [repeatable smoke](../development/explicit-account-bindings-smoke.md).
Repo: `agent-locksmith`; start from current `origin/main`, not retired develop.
This replaces D1's earlier promise to preserve implicit registration defaults.

## Problem and outcome

On baseline `5d606d5` / 2.8.0, missing per-agent env credentials and override-store
failure can dispatch under the registration's shared account. Empty credentials
also dispatch upstream. An agent without an override implicitly inherits the
registration account. The owner's pre-change local risk proof (kept separately from this shipped
contract) reproduces these behaviors using real application/database code.

An owner must explicitly bind an allowed agent to an upstream credential source.
Several agents may share the same binding/reference. A failed selection or
resolution must never change account or dispatch without the required credential.
Success is zero upstream operations on every denied/failed-selection case, with
correct account attribution on every allowed case and a usable upgrade path.

## Required behavior

1. Authenticate the agent, enforce its existing registration ACL, then find its
   explicit selection before resolving any upstream credential. Existing override
   records can supply this selection; no new catalog framework is required.
2. Missing selection is a denial (403). Missing/empty/unreadable/corrupt/revoked
   selected credentials or failed selection-store reads are unavailable (503).
   Missing/invalid required agent identity is 401. Use existing error envelopes;
   preserve existence hiding. All these cases make zero upstream operations.
3. Resolve only the selected source. No registration-default account, arbitrary
   cached credential, implicit OAuth label, unauthenticated forward or retry under
   another identity is permitted. A label literally named `default` is valid only
   when explicitly selected; its spelling does not authorize fallback.
4. Cover all already supported AuthSpec sources: env header/bearer, sealed stored
   header/bearer, 1Password header/bearer, PKCE and device-code OAuth sessions.
   OAuth refresh stays inside the selected registration/session/account.
5. Credential-free use is explicit owner configuration (`AuthSpec::None`) and
   still subject to existing admission policy. A missing credential is never
   converted to no-auth. An explicit owner-set per-agent no-auth selection remains
   distinguishable from absent selection. Broader grant migration remains D4.
6. Clearing a binding removes access to credentialed use; it does not reveal a
   registration default. Replacing it affects subsequent admissions. A change to
   the registration template cannot silently repoint already explicit selections.
7. Credentialed legacy `config.tools`/M0 or shared-bearer routes without a resolved
   agent identity must fail closed. Do not invent a privileged synthetic agent or
   bypass this requirement. Reuse existing agent registration/auth for upgrade;
   give an actionable startup/readiness diagnostic for incompatible configurations.
8. Audit allowed account/source selection and denied failure class using safe
   identifiers. Error responses, logs, plan files and read APIs never reveal
   upstream values, tokens, authorization headers or sealed plaintext.

## Operator migration and cutover

- Inventory active agents, effective current ACLs, current registrations and
  explicit override rows. Report identityless legacy paths separately.
- Produce a deterministic, read-only plan of proposed explicit selections for
  currently allowed routes only. Preserve explicit selections; do not resolve,
  unseal or export values. Reference shared env/stored/op/OAuth sources directly.
- Normalize an inherited OAuth session into an explicit label where its prior
  selection is known. Flag ambiguous, disabled, missing-source and unsupported
  legacy cases for owner mapping; never guess a new account or broaden an ACL.
- Apply only an owner-selected, reviewed mapping using existing operator/migration
  patterns. Pin and verify relevant source state; reject drift instead of
  overwriting edits. Make application transactional where needed and idempotent.
- Capture one current registration set. Future entries/accounts never receive
  automatically copied bindings. Unmapped agents remain denied after cutover.
- Document backup, stopped-daemon/consistent-snapshot requirements, preview,
  apply, verification and rollback consequences. No compatibility mode may
  silently re-enable runtime fallback. A GUI or approval queue is not required.

## Four sequential issues

Each issue owns its production behavior, tests and relevant operator docs. The
final issue is end-to-end release acceptance, not a deferred unit-test bucket.

| Slice | Deliverable | Acceptance evidence | Depends on |
| --- | --- | --- | --- |
| AGENT-176 (D1.1) | Enforce explicit account selection on the real proxy | Two explicitly shared agents, one distinct account; absent binding/failed lookup/empty or missing env never reach upstream; clear denies; existing tests retain their real purpose | None |
| AGENT-177 (D1.2) | Apply the same boundary to existing custody and OAuth lifecycles | Stored tombstone/key failure, op cache failure, explicit/missing OAuth labels, failed/concurrent refresh stay on the selected source; identityless credentialed routes cannot bypass policy | AGENT-176 (D1.1) |
| AGENT-178 (D1.3) | Preview and apply the legacy shared-account upgrade | Deterministic read-only plan; explicit rows preserved; reviewed reference-only mapping; drift/ambiguous/M0 handling; atomic/idempotent application; post-cutover newly added entries do not gain credential bindings | D1.1, D1.2 |
| AGENT-179 (D1.4) | Demonstrate and document an operator cutover | Actual daemon + operator flow, selected accounts verified at upstream, failure/audit assertions, docs/CLI help and full checks; separate D4 failures remain visibly tracked | D1.1–D1.3 |

If any slice needs more than a few focused days, the lead should split it into
small deliverables without dropping migration or reopening implicit fallback.
The release must include enforcement and upgrade support together.

## Test and release gate

The [project completion gate](../development/project-completion.md) applies:
D1 must deliver a repeatable actual-daemon/CLI smoke command and documentation
updates, with QA/reviewed evidence before completion. AGENT-179 owns that final
gate; AGENT-176–178 retain their per-change tests and relevant docs.

Use the [D1 acceptance matrix](2026-10-18-d1-acceptance-tests.md). Start with failing
regression tests against the current proxy, then the smallest implementation.
Mock external upstreams/1Password commands only; keep auth, repositories,
selection, sealing, refresh and forwarding real. Fixtures contain synthetic data.

Every denied/unavailable case must assert both its error class and **zero upstream
operations**. Count OAuth token exchanges separately. Positive cases identify the
actual upstream account. Do not make security tests pass by weakening assertions,
skipping cases or changing unrelated proxy-feature fixtures into denial-only tests.

```sh
cargo test --all
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

Baseline: 559 reported passes; two optional live-provider checks returned early
without provider keys. This is not provider compatibility evidence. The local
diagnostic currently reports 23 observations / 7 unsafe-contract outcomes.
Update its D1 expectations to the agreed policy; legacy public-entry ACL expansion
and stale activation remain D4 findings, not a reason to conceal failures.

Release demo: two allowed agents explicitly share account A, a third uses B.
Remove/fail A's binding/source and prove neither B, a registration template account,
nor an unauthenticated upstream is used. Restore the binding and verify normal
calls. Revoke an agent and show the next call is denied. Repeat after migration
and a daemon restart, then change the registration template and verify no drift.

## Boundaries and handoff

No Kamiwaza deployment, provider purchase/login, pool scheduler, SSO, UI, approval
queue, multi-tenancy, protocol expansion, full connection-schema migration or D4
cache-generation solution is needed. Keep one instance per security domain.

Historical execution guidance: work sequentially through implementation, QA and
independent review; record acceptance separately from integration and publication. Preserve the
owner's dirty working tree; use an isolated feature checkout from main and import
only the reviewed local docs/proof fixtures. No package/image publishing, pushes
or PR publication is authorized by this handoff. Return commits/diff, test evidence,
remaining limitations and a reviewable release/PR description to the user.
