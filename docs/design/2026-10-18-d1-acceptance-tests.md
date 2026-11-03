# D1 acceptance matrix

Companion to [Explicit account bindings](2026-10-18-d1-explicit-account-bindings.md).
Target: existing agent-locksmith HTTP proxy and custody implementations, local
synthetic accounts only. This historical matrix defines required acceptance;
results must name their exact revision and executed environment. See the
[saved smoke](../development/explicit-account-bindings-smoke.md) for the
repeatable actual-daemon/CLI checks and their limits.

## Enforcement and account attribution

| ID | Given / action | Required result |
| --- | --- | --- |
| S01 | Agents A/B have explicit selections of shared account X; C selects Y | Successful calls identify X/X/Y at upstream; caller auth never becomes upstream auth |
| S02 | ACL allows the registration but agent has no credential selection | 403; zero upstream operations and no credential-source use |
| S03 | Selection repository errors or contains corrupt AuthSpec | 503; zero upstream operations; no template/cached default account used |
| S04 | Selected header/bearer env value is absent or empty | 503 for each case; zero upstream operations; distinguish from explicit no-auth |
| S05 | Owner explicitly configures credential-free access | Existing ACL/auth rules apply; allowed call has no injected credential; no resolution required |
| S06 | Owner clears a previously valid binding | Next credentialed call denied; never inherits the registration account |
| S07 | Owner replaces X selection with Y | Subsequent admitted request uses Y only; no wrong-account retry |
| S08 | Registration template account changes after explicit selection | Existing selection remains X; newly unbound agents remain denied |
| S09 | Agent ACL removed, agent revoked or identity invalid | 403/401 as applicable; zero upstream operations; no credential resolution before denial |
| S10 | Legacy shared bearer / config.tools path cannot resolve agent identity | Credentialed route denied (401); actionable upgrade diagnostic; no synthetic privileged identity |

## Existing credential sources

| ID | Given / action | Required result |
| --- | --- | --- |
| C01 | Explicit sealed header/bearer binding resolves | Correct selected value injected; reads/audits never disclose it |
| C02 | Selected sealed value missing/tombstoned, wrong/missing key, failed read | 503; zero upstream operations; no alternate reference/account |
| C03 | Explicit 1Password header/bearer reference resolves | Selected cached source used; existing resolver lifecycle retained |
| C04 | Selected op reference unresolved, cache missing/failed, value empty | 503; zero upstream operations; registration default never substituted |
| C05 | Explicit OAuth PKCE/device-code session label exists | Intended session/account used; literal label `default` permitted only when explicit |
| C06 | OAuth label absent in selection, selected session missing or degraded | Reject malformed selection or 503 on unusable selection; healthy default session never used |
| C07 | Selected token expires and refresh succeeds/fails | Same selected session/account on success; 503 and zero upstream operations on failure |
| C08 | Six concurrent requests hit expired selected session | Existing lock ensures one successful refresh; all allowed calls retain selected account |
| C09 | Selected OAuth session revoked while another healthy label exists | Next admission fails; no default/other-label substitution |

Run both header and bearer variants, plus both supported OAuth AuthSpec variants
where they reach distinct code. A local fake op command/token endpoint represents
the external dependency; real custody/refresh/application behavior stays in use.
Caller inputs cannot supply an arbitrary credential reference or bypass operator
selection. An upstream auth error is not success for a zero-dispatch assertion.

## Migration and operator workflow

| ID | Given / action | Required result |
| --- | --- | --- |
| M01 | Existing explicit selection and implicit shared-account users | Preview preserves existing row; proposes only currently permitted known mappings |
| M02 | Run preview twice against identical state | Same ordered/reference-only plan; database/config unchanged; no values resolved/exported |
| M03 | Owner applies a reviewed plan then reruns it | Same bindings; no duplicate authority, secret copies or overwritten explicit edits |
| M04 | Registration/agent/policy/selection changes between plan and apply | Apply rejects stale relevant state; no partial/broader mappings |
| M05 | Revoked/expired agent, disabled entry, missing/ambiguous source | Plan flags/skips with reasons; owner must supply any unsupported mapping |
| M06 | Legacy identityless configuration | Upgrade steps use actual agent registration/auth; it is not silently mapped to an invented super-agent |
| M07 | A new credentialed entry/account is added after planning | No new selection/grant is created by rerun or daemon startup |
| M08 | Cutover/restart after approved migration | Explicit shared X/X and distinct Y remain correct; unresolved/unmapped callers denied |
| M09 | Apply fails midway | Transaction/rollback behavior leaves a consistent pre-apply state; existing selections preserved |
| M10 | Operator previews, sets, lists, clears and repairs bindings | CLI/API docs match behavior, list safe references/status only; clearing denies rather than resetting to default |

A migration rehearsal must use a temporary copy, synthetic env/stored/op/OAuth
references, allowed and denied agents, a legacy unrestricted agent, an existing
explicit override and at least one unresolved legacy mapping. This is not the
future full D4 ACL/connection migration. Do not auto-apply changes to this host's
running deployments while implementing/testing the migration tool.

## Required project smoke and documentation gate

AGENT-179 must save/document one repeatable smoke command using the **actual
daemon plus CLI/admin boundary**, temporary state and synthetic accounts. Reuse
an existing suitable runner where possible. These checks complement the full
regression matrix; component-only tests do not satisfy the smoke gate.

| ID | Smoke workflow | Required result |
| --- | --- | --- |
| SM01 | Start a disposable daemon and use the documented health/auth/setup flow | Configured instance starts; health/readiness and actual CLI/admin interaction behave as documented |
| SM02 | Two agents explicitly share X; a third selects Y | Receiving upstream identifies X/X/Y; inbound caller credentials are stripped |
| SM03 | Clear/break a selected binding and use missing/wrong caller auth | Expected denial/unavailable class, zero upstream operations and no alternate/default/unauthenticated dispatch; restore succeeds |
| SM04 | Preview/apply a reviewed legacy mapping, restart and call again | Preview is read-only; actual operator command works; explicit selections persist; stale/unmapped state fails safely |
| SM05 | Execute the revised setup/upgrade instructions in a fresh fixture | Documented commands/flags produce the stated outcomes; safe output and working links |

Record delivered commit, target/environment, exact command, exit code, assertions
and sanitized evidence. Missing prerequisites, skipped cases or a script that was
only written are not a passing run. Local upstream doubles are sufficient for D1;
they do not establish Kamiwaza or live-provider compatibility. Cleanup must stop
fixture processes and remove temporary state without altering real deployments.

Documentation changes must include the applicable per-agent credential concept,
CLI help/reference, getting-started/configuration, upgrade/migration procedure,
troubleshooting/error behavior and release notes. Remove advice that clearing a
selection restores a default account. List actual changed paths; QA/review must
check examples and smoke evidence before the project is marked complete. Follow
the [shared completion gate](../development/project-completion.md) for later projects.

## Evidence required per issue

- A regression that fails against the previous implementation for the named bug,
  then passes against the change; preserve meaningful existing feature coverage.
- Exact commands, exit codes, meaningful assertion/case counts and synthetic
  upstream account identities. Record unresolved cases rather than calling them passed.
- Error class plus zero upstream-operation counts on every failure. Count OAuth
  refresh exchanges and op resolution separately; positive cases prove both
  routing and selected account at the receiving endpoint.
- Audit assertions for agent/registration, safe selection/source identifiers,
  allowed/denied outcome and failure class; secret sentinels absent from logs,
  errors, admin reads, migration artifacts and persisted audit details.
- Full Rust test/Clippy/format checks before release acceptance. The final
  operator rehearsal includes actual daemon and CLI/admin boundary, not only
  in-process router tests. Each implementation issue includes its own tests.

No live Kamiwaza or provider quota claim follows from these checks. Existing
public no-auth ACL expansion and stale catalog activation remain separate D4
findings. No global network enforcement, active-stream cancellation or pool replay
safety claim is part of D1.
