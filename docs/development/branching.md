# Branching and releases

Effective 2026-10-18. This is the current branch policy for agent-locksmith and supersedes develop-based instructions in older engineering snapshots.

## Normal development

Effective 2026-11-13: changes land on `main` without pull requests.
GitHub Actions is off for this repository, so a PR adds no automated
gate; the gates are a local review and local tests.

- `main` is the integration branch and the base for new work. Keep it releasable.
- Work on a short-lived local `feature/`, `fix/` or `docs/` branch from current `origin/main`, one reviewable slice at a time.
- Before landing, run the tiered checks (see [local CI](local-ci.md)): fmt, clippy and the tests for the touched code on every change; the prior-binary migration checks when migrations or the schema change; QA smoke when a CLI command, an HTTP route or QA-exercised behaviour changes; the full suite and QA before a deploy and nightly.
- Run the two-engine [local review](review.md) on the branch diff, last, after every change you intend to land. Every change is reviewed, including docs-only and test-only changes, which use the docs/tests prompt. Critical and High findings block; fix them and review again. Other findings go to a follow-up ticket.
- Land with a fast-forward: `git switch main && git merge --ff-only <branch> && git push origin main`, then delete the branch.
- `develop` is retired as an integration branch. Do not base new branches on it.

For a clean checkout:

```bash
git fetch origin
git switch main
git merge --ff-only origin/main
git switch -c feature/my-change
```

Preserve any existing local changes before changing branches. Use a separate worktree when another task needs to keep its checkout/branch stable.

## Optional release branches

Normally release a tested commit from `main` with a version tag. Before tagging, build release binaries from a clean checkout of that commit and run `scripts/release-gate.py --bins <dir> --out <new dir>`: it runs the release-mode [QA gate](../../qa/README.md#statuses-and-gate) and checks that the bundle is release-ready and names that exact commit, clean. A release branch is useful only when stabilizing or maintaining a particular version while unrelated work continues on `main`.

- Cut `release/<major>.<minor>` from a selected tested `main` commit, not from `develop`.
- Limit it to stabilization, release metadata and fixes for that version. New features continue through feature branches into `main`.
- Apply fixes to `main` first and backport through a reviewed change where practical. If a fix starts on the release branch, carry it to `main` promptly through a focused change; do not lose it when the release branch is retired.
- Run the same local checks on a release branch as on `main`.
- Tag the tested release commit. Tags identify shipped versions; a release branch alone does not publish a release.
- Retain the release branch only while that release line needs maintenance.

## Building and publishing a release

GitHub Actions is off for this repository, so `.github/workflows/release.yml` and the [native validation](native-validation.md) workflow don't run; they are kept for when Actions returns (the long-term model is an open decision). They still build four targets, including darwin-amd64, which `scripts/release-notes.py` now refuses, so they need narrowing before they can publish again. A release is built, checked and published locally instead:

1. Pick the tested `main` commit, with [local CI](local-ci.md) passing at it, and run `scripts/release-gate.py` on release binaries built from it (above).
2. From an x86_64 Linux host, run `scripts/release-local.py --commit <sha> --out <dir outside the repo> --mac <user@host> --qemu <qemu-aarch64> --arm64-root <arm64 Linux root>`. It builds both programs with Rust 1.94.0 `--locked` from a fresh clone of the commit for the three shipped targets: linux-amd64 natively, linux-arm64 with `cargo zigbuild`, and darwin-arm64 on an Apple silicon Mac over SSH. Each pair is then smoke-tested where it can run (natively, or linux-arm64 under qemu-user). darwin-amd64 (Intel Macs) is not built or shipped, because no host here can smoke-test it; Intel Mac users build from source. `scripts/verify-build.py`'s checks must accept each pair against `SHA256SUMS` and refuse it for a wrong revision. Only then does it write `<dir>/assets/` with the six binaries `locksmith-SUFFIX` and `locksmithd-SUFFIX`, `SHA256SUMS` and `validation.json`, which records each asset's build host, `rustc --version --verbose`, target, revision and smoke result. It also writes `<dir>/notes.md` from the commit's `CHANGELOG.md` section. A failed or unreachable target makes it exit 1 naming the target, with no `assets/`. A rerun reuses targets already verified for that commit.
   - Prerequisites on the Linux host: Rust 1.94.0 with the `aarch64-unknown-linux-gnu` target, `cargo-zigbuild` with `zig` or the `ziglang` Python package (`--zig-path` puts its directory first on `PATH`), a user-mode `qemu-aarch64`, and an arm64 Linux root for its `-L`. On the Mac: Rust 1.94.0 with the `aarch64-apple-darwin` target, and Python 3.11 or later (`--mac-python`; the default runs 3.13 through `uv`).
3. Push the annotated tag `v<version>` at that commit, then `gh release create v<version> --verify-tag --notes-file <dir>/notes.md <dir>/assets/*`. Download the assets again and check them with `shasum -a 256 -c SHA256SUMS` and `scripts/verify-build.py`.

The `## <version>` section of `CHANGELOG.md` must exist before you build, and the tag must name the Cargo version.

Publishing/tag pushes follow the owner's release authorization; changing this branch policy does not itself authorize a release.

## Existing tooling and transition

GitHub's default branch is already `main`. The stack manifest sets agent-locksmith's branch to `main`, overriding the stack's general fallback preference. Other repositories retain their own policies.

At the transition check, `origin/main` contained all commits from `origin/develop`, and no open PR targeted `develop`. The local checkout was fast-forwarded to current `origin/main`, preserving existing uncommitted instruction/ignore changes and draft architecture documents. Existing develop references may remain as historical pointers; new work does not use them.

Historical files under `docs/archive/v2/` describe earlier releases and workflows. Their develop references, standing direct-merge instructions and old branch/version tables are not current operating instructions. Use this policy and the actual Git refs/tags for current work.
