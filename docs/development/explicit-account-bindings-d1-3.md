# Reviewed binding migration (AGENT-178)

Base: accepted D1.2 `afc3b96`. This adds an offline owner workflow over the existing
SQLite schema, rather than a remote migration API or runtime fallback.

## Delivered behavior

`locksmith migrate-bindings preview` opens an existing database read-only and
builds a deterministic JSON plan in one read transaction. Explicit column
projections exclude agent/bootstrap hashes, sealed credential bytes, nonces and
OAuth token blobs. Legacy YAML inventory does not use AppConfig expansion or
import credential values. Only reviewed `selected` flags on proposals may change.

Apply validates metadata and current eligibility inside `BEGIN IMMEDIATE`,
regenerates the canonical plan, and inserts absent selected bindings only. The
receipt and migration-local revision use namespaced `registrations_meta` keys;
they commit atomically with bindings and have no runtime reader. A repeat checks
the exact reviewed subset, expected post-state and selected eligibility. Later
clear/edit, missing receipt with retained revision and invalid metadata refuse
without recreating or overwriting choices. Unrelated metadata is preserved.

The inventory reuses `AgentIdentity::allows_tool` and the shared OAuth consensus
helper used by inline/background refresh. Corrupt selection metadata, conflicting
OAuth metadata, unavailable session metadata, placeholders, invalid references,
revoked/expired/denied agents and disabled registrations receive safe reasons.
Env/op and sealed-source metadata remain explicitly unverified. Known inherited
OAuth defaults become literal selected labels; existing incomplete selections
are never repaired from a changed template. File sources require owner mapping.

## Proof map

`cargo test --test binding_migration_test` uses actual offline CLI subprocesses,
SQLite repositories and registered-agent authentication. Only receiving upstreams,
token endpoints and the op executable are synthetic.

| Requirement | Evidence modules under tests/binding_migration |
| --- | --- |
| M01–M02 | contracts, inventory, metadata, oauth: deterministic/no-write projection, existing rows, ACL deny-wins, value/hash/blob sentinels, fake op and separate token counters |
| M03–M04 | contracts, drift, receipts: selected subset, exact repeat, later edit/clear, deleted/corrupt receipt, relevant contents/lifecycle drift and expiry after planning |
| M05–M06 | inventory, oauth: revoked/expired/disabled/missing/conflicting/unsupported/identityless reasons; real identity workflow linked for remediation |
| M07 | receipts, runtime: frozen set; later credentialed entry receives no binding, old plan refuses drift, actual request denies |
| M08 | runtime: CLI-migrated X/X plus prior distinct Y survive SQLite close/reopen; real sealing/custody/authentication/forwarding identifies accounts; missing/broken/revoked callers make zero additional upstream requests |
| M09 | contracts, receipts: failure on second insert or receipt insert rolls back all bindings and bookkeeping; private SQL error text stays out of output |

The accepted-base binary was built before feature edits using the physically
separate `target/agent177-baseline` directory. The first four CLI regression
contracts failed on that binary because the command was absent. Candidate
artifacts use ordinary `target`; no targets or dependencies are symlinked.
Further failing regressions exposed a shell-style environment-name restriction
and an OAuth malformed-store proposal mismatch in the first implementation;
both have dedicated corrected coverage. Environment names follow the runtime's
OS namespace rather than shell assignment syntax.

The [operator guide](../user/concepts/migrating-account-bindings.md) documents
WAL-safe backup, private preview/review/select/apply/verify, availability limits
and rollback consequences. A disposable CLI/SQLite rehearsal executes the backup
and migration flags, verifies repeat=0 and later-clear refusal, and cleans up.
The CLI reference and per-agent concept guide link this procedure. The shared
[completion policy](project-completion.md) is an intentional project input.

## Delivery boundary

AGENT-179 retains SM01–SM05: saved actual-daemon/CLI project smoke and final setup,
upgrade and documentation validation. The migration regression target's actual
CLI plus in-process runtime checks do not replace that project smoke. No live
provider compatibility, installed-daemon migration, release acceptance or D4
ACL/catalog-generation redesign is claimed. README/CLAUDE map residue stays with
AGENT-179. No schema/dependency/version/changelog changes or publication.


## Initial candidate verification (superseded by F1)

Local Darwin arm64, Rust/Cargo 1.94.0, candidate based on accepted `afc3b96`:

- `cargo test --test binding_migration_test`: 21 passed, 0 failed/ignored.
- `env -u OPENAI_API_KEY -u ANTHROPIC_API_KEY OLLAMA_HOST=127.0.0.1:0
  LMSTUDIO_HOST=127.0.0.1:0 cargo test --all --no-fail-fast -- --show-output`:
  exit 0, 624 reported passes, 0 failed/ignored. OpenAI, Anthropic, Ollama and
  LM Studio deliberately returned early; these four reports are not live-provider
  coverage.
- `cargo build --bins`, `cargo clippy --all-targets -- -D warnings`,
  `cargo fmt --check`, `git diff --check`: exit 0.
- Actual `migrate-bindings preview --help` and `apply --help`: exit 0.
- Disposable documented-command rehearsal: SQLite CLI read-only WAL backup and
  integrity check, deterministic same-config preview, selected apply=1/repeat=0,
  later-clear exit 5, no secret sentinels in output, temporary state cleaned.
- `env -u LOCKSMITH_LOCAL_PROOF_MISSING
  LOCKSMITH_LOCAL_PROOF_SELECTED=proof-selected LOCKSMITH_LOCAL_PROOF_EMPTY=
  cargo run --example local_risk_proofs`: exit 1 with exactly the two retained D4
  findings (21/23 matching). This is not a clean diagnostic/conformance pass.

The earlier unnecessary test-helper borrows failed strict Clippy and were fixed;
all final checks above include the corrections. Full intermediate logs and exact
final revision are retained in the builder handoff report rather than committed
with workstation paths or ephemeral artifacts.


## Reviewer F1 correction

Independent review rejected `1b2d14d` despite its green committed suite: supplied
legacy prefixes could be discarded in a selectable Header proposal, and changing
a supplied YAML env reference did not invalidate review. Both unchanged reviewer
probes were reproduced failing before this fix; no red commit was created.

The legacy inventory now retains safe source shape/header/env metadata, including
single legacy-string variable names via the existing bootstrap parser. It never
exports or hashes prefix/string values. Automatic implicit mappings require a
known wire-equivalent unprefixed env Header or no-auth source. Other shapes,
mismatched references and duplicate names require owner mapping. Explicit rows
remain preserved and unrelated proposals stay usable. Fresh supplied metadata is
checked under the existing SQLite transaction, including exact-repeat handling.
New tests cover stale reference/header/shape/omission, raw-env positives, literal
non-disclosure, forced-selection refusal, explicit preservation and a real
403/zero-upstream legacy route beside a usable unrelated route. Older plans must
be regenerated with the new reference inventory. Runtime/bootstrap behavior and
account/policy schema are unchanged; only bootstrap's pure reference parser is
shared with the inventory.


F1 verification: both exact-source reviewer probes pass (2/2); the focused
migration target passes 27/27; full `cargo test --all --no-fail-fast --
--show-output` reports 630 passed, 0 failed/ignored. OpenAI/Anthropic keys were
excluded and Ollama/LM Studio endpoints disabled; the same four provider tests
return early, not compatibility coverage. Debug binaries, strict all-target
Clippy, fmt/diff, the disposable documented WAL backup/CLI workflow and revised
guide links pass. Diagnostic remains exit 1, 21/23, only the two known D4 findings.
AGENT-179 actual-daemon project smoke remains pending. The exact new fix commit,
commands, reviewer-probe hashes and preserved red/green logs are in its handoff.
