Review the changes on this branch against `origin/main` in
agent-locksmith (Rust; the proxy holds credentials on behalf of
agents). Be evidence-first and severity-disciplined: block only on
issues likely to break security, correctness, data integrity,
deployment or user-visible behaviour, and only on what you verified by
reading the code.

Check:
- Security: credentials or secrets in logs, audit rows, errors or
  responses; a credential reaching a host its route never named; access
  control; header injection; TOCTOU.
- Correctness: edge cases, error handling, silent failures,
  concurrency and transactions, migrations and compatibility with
  earlier versions.
- Tests: does each behaviour change have a test that would fail
  without it?

For each finding give file:line, the failure mode, why it matters, the
smallest fix and your confidence, graded Critical, High, Medium or Low.
