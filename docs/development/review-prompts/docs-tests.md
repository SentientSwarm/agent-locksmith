Review the changes on this branch against `origin/main` in
agent-locksmith. They touch documentation, tests or the QA harness
only. Block only on what would mislead a reader or weaken the test
suite, and only on what you verified.

For documentation, check:
- Accuracy against the code as it is now: commands, flags, defaults,
  error codes, file paths and versions.
- Anything that would lead an operator to an unsafe setup, such as
  exposing credentials or overstating a protection.
- Broken links and references to retired features.
- No private hostnames, addresses or agent names (the repository is
  public).

For tests, check:
- Each test would fail if the behaviour it names broke. Look for
  assertions that cannot fail, mocks that test themselves, and skipped
  or ignored cases.
- No timing, port or ordering assumptions that make it flaky.
- No credentials or real secrets in fixtures.

For each finding give file:line, what is wrong, why it matters and the
smallest fix, graded Critical, High, Medium or Low.
