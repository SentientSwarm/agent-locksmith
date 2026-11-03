# Explicit account cutover smoke

Saved target: `tests/explicit_binding_smoke_test.rs`, with small support modules
under `tests/explicit_binding_smoke/`. It reuses the repository's CLI E2E
child/TempDir pattern and existing wiremock/reqwest/SQLite dependencies. It is
separate from the detailed in-process custody/refresh matrices.

## Run

The smoke was tested on Unix with Rust 1.94.0 and the committed `Cargo.lock`;
this is a tested toolchain, not a claim that earlier Rust versions are supported.
Use a C toolchain, Bash, `kill`, `sqlite3`, Python 3 and `curl` on PATH, from this checkout:

```sh
cargo build --locked --bins
cargo test --locked --test explicit_binding_smoke_test -- --nocapture
```

No accounts, login, installed daemon, external API or application DB is needed.
Cargo chooses binaries from this checkout using `CARGO_BIN_EXE_*`; do not share
artifacts/target symlinks with another checkout. Children start with an empty
environment plus PATH and synthetic fixture inputs, so inherited provider keys,
admin URLs, proxies and sealing keys cannot become test dependencies. The empty
seed path prevents importing an installed catalog. Debug version comes from the
actual daemon's `/version`; the CLI is the same built crate.

## Assertions by effect

| Gate | Executed effect |
| --- | --- |
| SM01 | Offline CLI operator bootstrap; documented YAML; actual daemon; bounded ready/live checks; real CLI UDS agent registration/status; missing/wrong operator auth exits 3. |
| SM02 | Actual HTTP receiver sees X/X/Y for A/B/C. Each success adds exactly one accepted operation for that account and one received request. Caller Authorization and API key cannot reach it. |
| SM03 | Generic/personalized actual `/skill` preserves cache/isolation and explains audit reasons and source health. Its rendered operator audit/list/set commands diagnose and repair both missing binding and unavailable selected source to X without changing grants; clear denies again. Missing/wrong/revoked caller 401; absent/cleared selection 403; missing/empty selected env 503. Every denial asserts class plus unchanged receiving-request **and** operation counts. Replacement, repair, catalog-template change, revoke-after-use and explicit no-auth controls exercise normal CLI paths. |
| SM04 | Stop/reap actual daemon; execute SQLite backup/integrity, deterministic reference preview and reviewed apply; supplied-reference drift fails with no insert; apply 2/repeat 0; start new daemon with same DB and observe X/X/Y. Preserve C, skip unsupported prefix, deny unmapped/new entry. Later clear plus old-plan refusal cannot recreate authority; deliberate rebind succeeds. |
| D4 lifecycle | Actual issuance/bootstrap enrollment/replay denial, own-token rotation preserving ID/expiry/policy/binding, old/wrong/expired/revoked token and cross-agent admin denial; X/Y receiving attribution. |
| D4 finite cutover | Explicit historical restricted/unrestricted/empty policies in a disposable stopped DB; before-review denial; actual preview/review/apply/repeat with zero inserts and preserved bindings; restart X/X/Y. New authless and credentialed names remain denied even after setting bindings. Stale reviewed-plan replay conflicts. |
| D4 activation/lifecycle | Corrupt an unrelated disposable registration; actual CLI write saves but exits 1 on refresh failure. Pending route503/zero arrivals, healthy route200, honest catalog and readiness. Stop, repair isolated row, restart activates saved state. Seed disable/re-enable preserves choices; operator destination replacement and hard-delete/recreate remove them and require deliberate reapproval. Revoke denies next admission. |
| D4 customer | Launch shipped Python reference API and observe X/X/Y plus unbound zero arrivals. Independently configured customer API uses a different path/header; execute shipped catalog/bind/grant/call blocks, diagnose missing finite grant via actual audit, inspect generic/personalized skill, observe customer-beta account. After receiving a delayed admitted request, clear selection; it completes but the next request is denied with no new arrival. |
| Service discovery | Execute shipped metadata-file publication for reference text and customer JSON operations. Construct scripted calls from runtime JSON, check X/X/Y/customer receiving attribution, metadata authority preservation, rejected input and legacy metadata. Compare personalized catalog names with `/tools` for each caller, including an unbound eligible caller; preserve generic/cross-agent isolation and do not invent a chat operation. This scripted proof is separate from independent consumer construction. |
| Connector validation | Reject malformed destinations, unsupported modes and narrower grant declarations through actual CLI/API calls before state changes. Preserve the existing registration, grant and selection, verify zero validation dispatch, then confirm the original account still works. |
| SM05 | Execute marked shell blocks from getting-started and migration guides, not copied shell recipes. Parse the marked empty-catalog YAML and substitute private fixture paths/unused port; add the unsupported-prefix legacy fixture during a separate stopped-process restart. Check CLI help, safe reads/audits/operational output and daemon logs. |

The receiver counts all arrivals separately from accepted operations. An upstream
401 cannot satisfy a zero-dispatch assertion. Synthetic secret/caller tokens are
kept in memory/private temp files, excluded from stdout. One-time bootstrap and
enrollment output is consumed privately. The named PASS/status/account counters
are suitable for a captured report; raw fixture state is not.

Readiness is bounded at 10s, HTTP at 5s and each short-lived CLI/tool process at
20s. Daemon guards kill/wait on failure; normal cutover sends SIGTERM, waits for
exit and only then runs offline migration. TempDir removes state on failure.
Successful cleanup explicitly checks removal and closed daemon/upstream ports.
A failed assertion makes the test command nonzero; required smoke has no skip or
early-return branch.

## Documentation validation and limits

Marked examples are executable test inputs: operator bootstrap, catalog put,
agent register/bind/status/clear/list, daemon start, SQLite backup, migration
preview/apply, reference API and customer-service setup/grant/call. CLI help checks cover the corresponding supported flags. Local
Markdown link validation is a separate delivery check; external URLs and actual
provider instructions are not live-tested by this target.

See [setup](../user/getting-started.md),
[credential concepts](../user/concepts/per-agent-credentials.md),
[migration](../user/concepts/migrating-account-bindings.md),
[CLI](../user/cli-reference.md),
[troubleshooting](../user/operator/account-binding-troubleshooting.md),
[change notes](../user/changes/explicit-account-bindings.md),
[contract](../design/2026-10-18-d1-explicit-account-bindings.md) and
[acceptance matrix](../design/2026-10-18-d1-acceptance-tests.md).

Run full `cargo test --locked --all`, `cargo clippy --locked --all-targets -- -D warnings`,
`cargo fmt --check` and `cargo build --locked --bins` as separate checks.
Optional provider tests may return early; disclose them rather than claiming
provider compatibility. `local_risk_proofs` records the older baseline's two D4
findings (legacy unrestricted ACL growth and stale activation); that historical
diagnostic is not the current acceptance oracle. Focused `http_grants_test` and
`http_activation_test` cover strict DTOs, atomic issuance/cleanup races, coherent
admission, YAML fallback denial and unreadable-row discovery.

This smoke does not verify installed deployments, real OAuth/op services,
TLS/mTLS transport, live provider behavior, active-stream cancellation or pool
replay safety. Focused tests retain the D1 custody/refresh variants. Independent
QA first exercises the shipped consumer docs without private test/setup recipes,
then checks the exact candidate. Reviewer source review proceeds independently;
execution is serialized through the team's test slot. Lead acceptance requires
both verdicts.

For connector-onboarding acceptance, retain the independent consumer's
original code and allowed-input bundle separately from these scripted tests.
Repeat/extend the public-docs/discovery journey with a fresh ordinary identity at
the final immutable revision before inspecting implementation or test bodies.
The [project change notes](../user/changes/connector-onboarding.md) record upgrade
and compatibility boundaries; the final delivery record names actual commands,
exits, environment and separate consumer/QA/reviewer evidence.
