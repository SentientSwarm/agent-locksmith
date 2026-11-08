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

More journeys follow the same pattern: credential custody, agent enrolment
and mTLS, OAuth services, native MCP tools, audit and monitoring, and
day-two operations.

## Conventions

- Commands run in a POSIX shell (Bash or zsh) on Linux or macOS.
- `$LOCKSMITH_HOME` is the private directory that holds this instance's
  configuration, database and credentials. The journeys use
  `~/locksmith`; choose your own.
- Values such as tokens are kept in environment variables and never printed.
  In the figures they appear as `<redacted:…>`.

## How the guide is tested

`qa/run.py --suite uat` runs each journey in a fresh home directory with the
binaries under test first on `PATH`, and records an evidence bundle: one
transcript per command, every figure, and these pages rendered with that
run's figures. Commands that a run does not execute, such as building from
source, are listed in the bundle's `guide/NOT-EXECUTED.md`. See
[qa/README.md](../../qa/README.md#uat).
