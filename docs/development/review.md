# Local review

Every change to `main` gets a two-engine review of the branch diff
before it lands. There are no pull requests (see
[branching](branching.md)), so the review runs locally.

## How

1. Commit every change you intend to land first. The review runs last:
   a commit after it voids it.
2. Pick the prompt. A diff that touches only `docs/`, `*.md`, `tests/`
   or `qa/` uses the docs/tests prompt; anything else uses the code
   prompt.
3. Run both engines against `origin/main`, in parallel:
   - Codex: `codex review - < docs/development/review-prompts/<prompt>.md`.
     Codex does not accept a custom prompt together with `--base`; the
     prompt itself names `origin/main`. Check the output for findings,
     not the exit code: Codex exits 0 even when a run is cut short.
   - Claude: a fresh, isolated session given the same prompt and the
     diff (`git diff origin/main...HEAD`), reading files but not running
     builds.
4. Synthesize the two reports into one verdict: PASS or REVISE.
   - REVISE on any Critical or High finding, or any dimension under 7/10.
   - Fix, re-run the affected checks, and review again.
   - Everything else goes to a follow-up ticket; it is not a reason to
     push again.
5. Record the verdict and the reviewed commit on the tracking ticket,
   then fast-forward `main` to exactly that commit.

## Prompts

- [Code](review-prompts/code.md)
- [Docs and tests](review-prompts/docs-tests.md)

The files are the prompts as given to both engines, unedited.
