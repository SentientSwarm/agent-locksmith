# Local CI

GitHub Actions is turned off for this repository to save budget. The
`ci.yml` workflow is still the specification of CI; `scripts/ci-local.py`
runs it on a developer machine against one commit.

## When to run what

Tiered, per [branching](branching.md):

| When | Run |
|---|---|
| Every change | `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings` and the tests for the touched code |
| A migration or schema change | also `scripts/ci-local.py --jobs test`, which runs the prior-binary migration checks |
| A CLI command or HTTP route (any listener), or behaviour the QA smoke or UAT cases exercise (`qa/`, `docs/guide/`) | also `scripts/ci-local.py --jobs qa-smoke`. Its PR-mode gate fails when a command or route is missing from, or stale in, `qa/surface.yaml`, when a case fails, or when an area drops below its floor. It does not require a case for every entry: that is checked only by `qa/run.py --mode release`, which no local CI job runs, so add the cases yourself: a passing positive case for each entry, plus refusal cases for each refusal code it lists (see [QA](../../qa/README.md)) |
| Before a deploy, and nightly | `scripts/ci-local.py` (every job) on the commit being deployed |

## Test binaries

Integration tests are grouped into six suite binaries rather than one per file,
because every binary is linked, and on macOS vetted by `syspolicyd` the first
time it runs. With one binary per file, that check alone could stall a
parallel run for an hour. `Cargo.toml` sets `autotests = false` and lists
each binary.

| Binary | Holds |
|---|---|
| `admin_suite` | admin API, audit, operational logs, repositories, migrations, CLI |
| `catalog_suite` | registrations, HTTP services, routes, brokers, definitions, bindings |
| `mtls_suite` | mTLS validation and revocation, admin HTTPS |
| `native_suite` | in-process native MCP lifecycle, policy and dispatch |
| `oauth_suite` | OAuth admin, serde, seeding, device login, recovery |
| `proxy_suite` | the agent proxy, response controls, credential sources |

Each `tests/<binary>.rs` includes former test files unchanged, by path, as
modules named after the file. To run what used to be `--test streaming_passthrough_test`:

```bash
cargo test --test proxy_suite streaming_passthrough_test::
cargo test --test native_suite -- native_lifecycle_test:: native_state_test::
```

Filters are substring matches, so `admin_https_test::` also runs
`cli_admin_https_test::`, and `proxy_test::` also runs
`credential_store_proxy_test::` and `op_credential_proxy_test::`.

Thirty files stay as their own binaries: those that start real daemon, CLI
or SDK processes (in one binary, about fifty of them would start at once and
their startup deadlines would compete), those that change environment
variables or the process umask, re-run their own executable, resolve
helper modules from the crate root, or are named by `ci.yml`. A new test
file needs a line in one of the suite files, or its own `[[test]]` entry
if it does any of those things. With `autotests = false`, a file in
neither place would never be built; `test_inventory_test` (in
`admin_suite`) fails when any `tests/*.rs` is built other than exactly once.

[cargo-nextest](https://nexte.st) also works (`cargo nextest run
--workspace`), and is faster for touched-code runs, but `cargo test`
remains the gate. `.config/nextest.toml` limits the process-starting tests
to four at a time and retries them twice: running every binary's tests at
once exposes a probed-port race in some fixtures (AGENT-219), and a test
that passes only on retry is reported as FLAKY.

## Run it

```bash
python3 scripts/ci-local.py                    # HEAD, all jobs
python3 scripts/ci-local.py --rev <sha|ref>    # a specific commit
python3 scripts/ci-local.py --jobs qa-smoke
python3 scripts/ci-local.py --post-status      # also post commit statuses
```

Only committed code is tested: the commit is checked out in a separate
worktree, so local edits never leak into a result. The script itself runs
from your checkout, so commit runner changes before trusting a result. It
needs Python 3.11 or later with PyYAML, `uv`, `git`, Rust 1.94.0 (rustup) and, for `--post-status`,
an authenticated `gh`.

It exits 0 only when every selected job passes, and prints the evidence
directory: `ci.log` (every step's output), `summary.json` (commit, host
target, per-step results) and any uploaded artifacts, such as the QA and
UAT evidence.

`--post-status` posts a `local-ci/<job>` commit status (`success` or
`failure`) on the tested commit, so the result is recorded on GitHub
against that commit. A failed post stops the run with `gh`'s error.

## Jobs

| Job | Workflow | Notes |
|---|---|---|
| `test` | `ci.yml` | Builds the pinned prior binaries, runs `cargo test --all`, every migration and prior-binary refusal check, clippy, fmt and the MCP transport crate. |
| `qa-smoke` | `ci.yml` | Release build, QA harness tests, QA smoke and UAT. |

## How steps map

`run:` steps execute as written, with `bash -eo pipefail`,
`GITHUB_WORKSPACE`, `RUNNER_TEMP`, `GITHUB_SHA` and a working `GITHUB_ENV`.
`if: always()`, `if: failure()` and `if: success()` behave as on GitHub.

The environment starts from a short allowlist (`HOME`, `USER`, `PATH`,
`TMPDIR`, locale, `CARGO_HOME`, `RUSTUP_HOME` and a few more), not your
shell. Provider API keys in your shell would otherwise switch on paid live
tests, and `CARGO_*` or `BASH_ENV` would change what is built and run.

The runner fails closed on these settings it does not implement: any other `if:`
expression, step settings such as `working-directory`, `shell` or
`continue-on-error`, job settings such as `env`, `if` or `defaults`, and
workflow-level `defaults`. Add support to the script before using one.

`uses:` steps get a local equivalent:

| Action | Local equivalent |
|---|---|
| `actions/checkout` (no `ref`) | the tested commit's worktree |
| `actions/checkout` with `ref` and `path` | a cached worktree of that commit, linked at `path` |
| `dtolnay/rust-toolchain@V` | checks that rustc `V` is available (rustup toolchain first) |
| `astral-sh/setup-uv` | checks that `uv` is on `PATH` |
| `actions/upload-artifact` | copies the paths into the evidence directory |
| `Swatinem/rust-cache` | nothing: the target directory persists |

A step with no mapping stops the run. When a workflow gains a new action,
add its local equivalent to the script.

## Cache

Everything lives under `~/.cache/locksmith-ci/repos/<id>/` (override the
base with `LOCKSMITH_CI_CACHE`), one directory per clone, since a worktree
can only check out its own repository's commits. It holds the workspace
worktree and its `target/`, the pinned prior-source worktrees, the cached
prior binaries and `runs/<sha>-<time>/` evidence. The first run builds
every pinned prior binary; later runs reuse one only when its pinned
worktree is still at the recorded commit and the build step's text and
the compiler (`rustc --version --verbose`) are unchanged. The last 20 runs' evidence is
kept, without the runner's scratch directory. One run at a time holds
`lock`. Delete the directory to start clean (run `git worktree prune`
afterwards).

## Differences from GitHub

- The host is whatever machine runs it, usually macOS ARM64 rather than
  `ubuntu-latest`. Linux-only failures are not caught.
- `native-validation.yml` is not run. It is release provenance: it
  records the GitHub runner image and requires all four native runners
  (see [native validation](native-validation.md)), so a local run would
  have to invent that metadata. Releases still need it on GitHub.
- Artifacts stay on the machine rather than being uploaded.
- Steps run under `bash -eo pipefail`, stricter than GitHub's default
  `bash -e`: a failure inside a pipeline fails the step here.
- `with:` inputs other than the ones in the table are not enforced; for
  example `setup-uv`'s `version` only checks that `uv` exists.
