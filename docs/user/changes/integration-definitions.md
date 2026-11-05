# Integration definition authoring and upgrade

Operators can import strict immutable definitions and create disabled native
connections pinned to an exact revision. API and CLI use the same authenticated
backend. [Start here](../operator/integration-definitions.md). This additive
feature is included in the existing planned3.0.0; it causes no independent
version bump, tag, deployment or publication.

Migration0012 runs before listeners, adds definition storage and pin guards,
and preserves existing manual HTTP/native registrations, account custody,
selections, grants, revocations and receipts. It imports no definitions and
creates no account or authority. Existing native MCP config files remain valid;
new optional `mcp.definition` is server-managed through create-from-definition.

Stop the daemon and back up the whole SQLite database before upgrade, following
[native backup/recovery](native-mcp.md). Preserve both old binaries and the
matching pre-upgrade backup. An accepted schema11 binary refuses schema12 before
opening listeners. Rollback means stopping the new daemon and restoring that
complete backup with its matching binaries. Do not delete migration records or
manually strip pins to make an old executable open upgraded data.

After restart, inspect `locksmith integration get ID --revision N` and
`locksmith tool get NAME`. Saved/disabled is expected; readiness does not certify
any provider or selected credential. General enable, PUT and credential edits
of these derived rows are intentionally refused pending promotion contracts.
Use another name or deliberately delete/recreate; old authority is not revived.
A new definition revision never changes existing instances.

Verification covers strict imports, immutable collisions, exact pins, no partial
custody writes, actual disposable CLI/daemon operation with zero receiving TCP
connections, persistence and actual prior-binary refusal. Exact independent
QA/reviewer acceptance is tracked separately. Full AGENT-203 remains pending
195/196/200, with194 setup also unaccepted; consent, durable refresh, approved
tools, useful dispatch, live/client UAT and release gates remain outstanding.

The public source projection keeps root2.8.0 and preserves current HTTP/native
prerequisites. Its new exact-candidate process/consumer/prior-binary checks and
Linux CI remain receiving work; historical offline acceptance is not a current
runtime result or full AGENT-203 completion.
