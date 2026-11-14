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

Normally release a tested commit from `main` with a version tag. A release branch is useful only when stabilizing or maintaining a particular version while unrelated work continues on `main`.

- Cut `release/<major>.<minor>` from a selected tested `main` commit, not from `develop`.
- Limit it to stabilization, release metadata and fixes for that version. New features continue through feature branches into `main`.
- Apply fixes to `main` first and backport through a reviewed change where practical. If a fix starts on the release branch, carry it to `main` promptly through a focused change; do not lose it when the release branch is retired.
- Run the same local checks on a release branch as on `main`.
- Tag the tested release commit. Tags identify shipped versions; a release branch alone does not publish a release.
- Retain the release branch only while that release line needs maintenance.

Pushing a `v*` tag runs `.github/workflows/release.yml`. It calls the [native validation](native-validation.md) workflow, which builds both programs with Rust 1.94.0 on a native runner for each of the four targets and smoke-tests them. It then checks that the tag names the Cargo version and that the aggregated bytes match `SHA256SUMS`, and publishes exactly those bytes: `locksmith-SUFFIX` and `locksmithd-SUFFIX` for each target, `SHA256SUMS` and `validation.json`. The release notes are the version's section of `CHANGELOG.md`, so that section must exist before tagging. The publish job also requires a successful CI push run for the tagged commit, which CI only produces on `main` and `release/**`: tag a commit after its CI has passed. Pull requests that change the release path, and manual runs, do everything except publish. If only the publish job fails, "Re-run failed jobs" reuses the validated artifact instead of rebuilding.

Publishing/tag pushes follow the owner's release authorization; changing this branch policy does not itself authorize a release.

## Existing tooling and transition

GitHub's default branch is already `main`. The stack manifest sets agent-locksmith's branch to `main`, overriding the stack's general fallback preference. Other repositories retain their own policies.

At the transition check, `origin/main` contained all commits from `origin/develop`, and no open PR targeted `develop`. The local checkout was fast-forwarded to current `origin/main`, preserving existing uncommitted instruction/ignore changes and draft architecture documents. Existing develop references may remain as historical pointers; new work does not use them.

Historical files under `docs/v2/` describe earlier releases and workflows. Their develop references, standing direct-merge instructions and old branch/version tables are not current operating instructions. Use this policy and the actual Git refs/tags for current work.
