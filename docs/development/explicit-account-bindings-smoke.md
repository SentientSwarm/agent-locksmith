# Explicit account cutover smoke

Saved target: `tests/explicit_binding_smoke_test.rs`, with small support modules
under `tests/explicit_binding_smoke/`. It reuses the repository's CLI E2E
child/TempDir pattern and existing wiremock/reqwest/SQLite dependencies. It is
separate from the detailed in-process custody/refresh matrices.

## Run

The smoke was tested on Unix with Rust 1.94.0 and the committed `Cargo.lock`;
this is a tested toolchain, not a claim that earlier Rust versions are supported.
Use a C toolchain, Bash, `kill` and `sqlite3` on PATH, from this checkout:

```sh
cargo build --bins
cargo test --test explicit_binding_smoke_test -- --nocapture
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
| SM03 | Generic/personalized actual `/skill` preserves cache/isolation, explains audit reasons and source health, and its rendered operator list/set commands diagnose and repair an unbound agent to X; clear denies again. Missing/wrong/revoked caller 401; absent/cleared selection 403; missing/empty selected env 503. Every denial asserts class plus unchanged receiving-request **and** operation counts. Replacement, repair, catalog-template change, revoke-after-use and explicit no-auth controls exercise normal CLI paths. |
| SM04 | Stop/reap actual daemon; execute SQLite backup/integrity, deterministic reference preview and reviewed apply; supplied-reference drift fails with no insert; apply 2/repeat 0; start new daemon with same DB and observe X/X/Y. Preserve C, skip unsupported prefix, deny unmapped/new entry. Later clear plus old-plan refusal cannot recreate authority; deliberate rebind succeeds. |
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
preview/apply. CLI help checks cover the corresponding supported flags. Local
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

Run full `cargo test --all`, strict all-target Clippy and fmt as separate checks.
Optional provider tests may return early; disclose them rather than claiming
provider compatibility. `local_risk_proofs` remains a diagnostic with two known
D4 failures (legacy unrestricted ACL growth and disabled-row stale activation),
not a passing conformance target. This smoke does not verify installed deployments,
real OAuth/op services, TLS/mTLS transport, live provider behavior, active-stream
cancellation or pool replay safety. Focused tests retain those D1 source variants
that need distinct failure/refresh coverage. Independent QA then reviewer execute
the saved smoke and inspect docs at the delivered commit before lead acceptance.
