# Local CI

GitHub Actions is turned off for this repository to save budget. The
`ci.yml` workflow is still the specification of CI; `scripts/ci-local.py`
runs it on a developer machine against one commit.
A local CI pass on the head commit is the CI requirement for merging.

## Run it

```bash
python3 scripts/ci-local.py                    # HEAD, all jobs
python3 scripts/ci-local.py --rev <sha|ref>    # a specific commit
python3 scripts/ci-local.py --jobs qa-smoke
python3 scripts/ci-local.py --post-status      # also post commit statuses
```

Only committed code is tested: the commit is checked out in a separate
worktree, so local edits never leak into a result. The script needs Python
with PyYAML, `uv`, `git`, Rust 1.94.0 (rustup) and, for `--post-status`,
an authenticated `gh`.

It exits 0 only when every selected job passes, and prints the evidence
directory: `ci.log` (every step's output), `summary.json` (commit, host
target, per-step results) and any uploaded artifacts, such as the QA and
UAT evidence.

`--post-status` posts a `local-ci/<job>` commit status (`success` or
`failure`) on the tested commit, so the result shows on the PR.

## Jobs

| Job | Workflow | Notes |
|---|---|---|
| `test` | `ci.yml` | Builds the pinned prior binaries, runs `cargo test --all`, every migration and prior-binary refusal check, clippy, fmt and the MCP transport crate. |
| `qa-smoke` | `ci.yml` | Release build, QA harness tests, QA smoke and UAT. |

## How steps map

`run:` steps execute as written, with `bash -eo pipefail`,
`GITHUB_WORKSPACE`, `RUNNER_TEMP`, `GITHUB_SHA` and a working `GITHUB_ENV`.
`if: always()` and `if: failure()` behave as on GitHub. `uses:` steps get
a local equivalent:

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

Everything lives under `~/.cache/locksmith-ci` (override with
`LOCKSMITH_CI_CACHE`): the workspace worktree and its `target/`, the
pinned prior-source worktrees, and `runs/<sha>-<time>/` evidence. The
first run builds every pinned prior binary; later runs reuse them. One
run at a time holds `lock`. Delete the directory to start clean (run
`git worktree prune` afterwards).

## Differences from GitHub

- The host is whatever machine runs it, usually macOS ARM64 rather than
  `ubuntu-latest`. Linux-only failures are not caught.
- `native-validation.yml` is not run. It is release provenance: it
  records the GitHub runner image and requires all four native runners
  (see [native validation](native-validation.md)), so a local run would
  have to invent that metadata. Releases still need it on GitHub.
- Artifacts stay on the machine rather than being uploaded.
