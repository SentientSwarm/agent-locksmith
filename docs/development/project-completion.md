# Project completion: smoke tests and documentation

Applies to every agent-locksmith delivery project, including D1 and future
projects in the incremental roadmap. Smoke tests and documentation updates are
required deliverables, planned with the feature and verified before completion.

## Include when defining a project

- Name a repeatable smoke-test command or existing test target, the target
  runtime/environment, prerequisites, owner and evidence location.
- Specify the main user/operator workflow and at least one meaningful failure
  or denial case. Assert the promised outcome and side effects, not just HTTP 200.
- Name the documentation files to update: user/quick-start, CLI/API/configuration,
  authentication, upgrade/migration, troubleshooting or architecture/developer
  guidance as appropriate. Assign them within the delivery issues.
- Put smoke and documentation acceptance in the project's final delivery gate;
  each implementation issue still owns its own regression tests and relevant docs.

## What counts as a smoke test

Use the real changed application boundary. For runtime projects, launch the actual
daemon/application and exercise its CLI/API/protocol as a user would. A unit test
or in-process router test alone is insufficient. For design/documentation-only
projects, execute their documented runnable examples/proofs and check their
referenced contracts and links; do not invent unrelated application work.

Prefer existing scripts/test targets. Keep the smoke deterministic and bounded,
with temporary fixtures, synthetic credentials, isolated ports/state, failure
exit codes and cleanup. External upstreams may be local test doubles; record that
scope. A mocked provider does not prove live platform/provider compatibility.
If the project requires a real deployment, include its smoke run in that project's
acceptance and keep it visibly pending until it is executed.

Run the required smoke against the delivered revision after relevant changes.
Record the commit, environment/version, command, exit code, assertions/results
and sanitized artifact location. Missing inputs, skipped cases and an unexecuted
script are not passing evidence. Smoke complements the normal regression suite,
lint and formatting checks; it does not replace them.

## Documentation delivery

Update docs with the implementation. Commands, flags, examples, error behavior,
defaults and migration advice must match the delivered behavior. Validate runnable
instructions in the smoke fixture and check local links. Do not include secrets
or imply verification against environments that were not exercised.

Each project ships appropriate documentation changes. Internal-only work can
update the design/developer guide or operational runbook; it does not require an
unrelated user-guide rewrite. List the changed files and what a reader can now do.

## Completion evidence

- [ ] Required smoke command is saved and documented; positive and negative
  workflows were executed against the delivered revision with expected results.
- [ ] Sanitized smoke evidence names the revision, target, command and exit code;
  any unverified live-system capability is explicitly distinguished.
- [ ] Relevant documentation changes ship with the project; examples/links were
  checked and behavior-changing upgrades have migration/troubleshooting guidance.
- [ ] QA/reviewer verifies both smoke evidence and documentation accuracy before
  the lead marks the project complete. Existing completed issues remain history;
  any missing project-level evidence is completed in the current acceptance issue.

## Reusable project brief fields

```text
Smoke command/target:
Prerequisites and fixture/environment:
Positive workflow and expected result:
Failure/denial workflow and expected side effects:
Evidence artifact and delivered revision:
Documentation files and changes:
Validation of examples/links:
QA/review evidence and remaining live-system limits:
```
