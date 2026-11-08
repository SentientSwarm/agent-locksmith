# Locksmith user guide

Locksmith holds the credentials your agents use. An agent proves who it is to
Locksmith, and Locksmith calls the upstream service on its behalf with the
account an operator selected for it. The agent never sees the credential.

This guide is a set of journeys, each one a task you do end to end. Every
journey is also an acceptance test: the UAT runs the commands on these pages
exactly as written and checks the results. The figures are captured from
those runs, so what you see is what the current release does.

| # | Journey | You will |
|---|---|---|
| 1 | [Install and first run](01-install.md) | install the binaries, mint an operator credential, start the daemon and check it |
| 2 | [Connect an HTTP service](02-http-service.md) | register a service, register an agent, select its account, call through Locksmith, deny and repair |
| 3 | [Keep credentials in Locksmith](03-credential-custody.md) | seal credentials under a key, select 1Password references, see fail-closed behaviour |
| 4 | [Enrol agents](04-enrol-agents.md) | enrol with bootstrap tokens, identify agents by client certificate, revoke a certificate |
| 5 | [Connect an MCP service](05-mcp-service.md) | observe an MCP server, review and grant one tool, use it as the agent |
| 6 | [Connect an OAuth service](06-oauth-service.md) | declare a provider contract, approve access in the browser, let an agent act as the account |
| 7 | [Audit and monitor](07-audit-and-monitor.md) | configure the audit, operational and process logs, watch health, read who did what |
| 8 | [Day-two operations](08-operate.md) | rotate agent and operator tokens, back up and restore, revoke an agent |

Not yet covered here: upgrading an existing 2.x instance (see the
[change notes](../user/changes/)) and running Locksmith as a system service
(see the hardened unit in `dist/systemd/`).

## Conventions

- Commands run in a POSIX shell (Bash or zsh) on Linux or macOS.
- `$LOCKSMITH_HOME` is the private directory that holds this instance's
  configuration, database and credentials. The journeys use
  `~/locksmith`; choose your own.
- Each journey uses more than one terminal. Run journey 1's
  [home block](01-install.md#choose-a-home-for-this-instance) in every
  terminal you open; it sets the directory and every port the journeys use.
- Values such as tokens are kept in environment variables and never printed.
  In the figures they appear as `<redacted:…>`.
- Ports in the figures are whichever free ports the test run chose, not the
  defaults on the page.

## How the guide is tested

`qa/run.py --suite uat` runs each journey in a fresh home directory with the
binaries under test first on `PATH`, and records an evidence bundle: one
transcript per command, every figure, and these pages rendered with that
run's figures. Commands that a run does not execute, such as building from
source, are listed in the bundle's `guide/NOT-EXECUTED.md`. See
[qa/README.md](../../qa/README.md#uat).
