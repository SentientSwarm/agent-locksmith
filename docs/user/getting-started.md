# Run a standalone development instance

Locksmith authenticates a registered agent, checks its ACL, then uses that
agent's explicit account selection. Creating a catalog entry alone grants no
account access. Start with a disposable instance before upgrading a deployment.

## Prerequisites and saved smoke

This flow was tested with Rust 1.94.0 and the committed `Cargo.lock`. Lower
toolchains have not been validated here; edition 2024 alone does not establish
the locked dependencies' minimum. Use a C toolchain, Bash and `sqlite3` on Unix.
Manual HTTP checks below also use `curl`. Build from the repository root:

```sh
cargo build --bins
cargo test --test explicit_binding_smoke_test -- --nocapture
```

The saved SM01–SM05 test starts actual debug `locksmithd` and `locksmith`
processes with temporary configuration, database, operator credentials and
loopback listeners. It supplies a synthetic receiving API, executes the marked
command examples below and in the [migration guide](concepts/migrating-account-bindings.md),
checks X/X/Y accounts and zero-dispatch failures, stops/restarts the process for
migration and removes fixture state. No provider account, installed service,
`op` login or owner database is used. Failure exits nonzero. See the
[cutover smoke contract](../development/explicit-account-bindings-smoke.md)
for counters, prerequisites and limits. A live provider deployment needs its own
receiving-account verification.

## Create an operator and configuration

For a manual instance, choose a private directory and unused loopback port.
Keep these variables in each terminal that uses the CLI; substitute your paths:

```sh
umask 077
export LOCKSMITH_BIN="$PWD/target/debug/locksmith"
export LOCKSMITHD_BIN="$PWD/target/debug/locksmithd"
export FIXTURE_DIR="$(mktemp -d)"
export CONFIG="$FIXTURE_DIR/config.yaml"
export SOCKET="$FIXTURE_DIR/admin.sock"
export DATABASE="$FIXTURE_DIR/locksmith.db"
```

<!-- smoke:operator -->
```sh
"$LOCKSMITH_BIN" bootstrap-operator --name smoke > "$FIXTURE_DIR/operators.yaml"
```

Stdout contains the operator's Argon2 hash; stderr displays its wire token once.
Save that token privately as `LOCKSMITH_OP_TOKEN`. Do not paste it into reports
or commit it. Replacing the operators file rotates credentials when the daemon
next loads it; minting alone does not change a running daemon's authenticator.

Write this YAML to `$CONFIG`, replacing the three relative paths with paths
inside your private directory and choosing an unused port:

<!-- smoke:config -->
```yaml
listen:
  host: "127.0.0.1"
  port: 9200
  auth_mode: bearer
  admin_socket:
    path: "./admin.sock"
operator_credentials_path: "./operators.yaml"
database:
  path: "./locksmith.db"
shutdown:
  drain_window_seconds: 1
tools: []
```

This intentionally starts with an empty catalog. `config.example.yaml` contains
legacy/provider examples; copying it is not required for this local flow.
For stored or OAuth sources, supply the corresponding independent sealing key
through normal secret custody before startup. Never put keys in the plan or YAML.

## Start and check the daemon

Choose a local API you control as `UPSTREAM_URL`. The smoke supplies its own
receiver. Set `SMOKE_X` and `SMOKE_Y` in the daemon environment to that API's
account credentials; these variable names are references, not literal credentials.
Keep this terminal running; the `exec` replaces its shell:

<!-- smoke:start -->
```sh
LOCKSMITH_SEED_PATH="" exec "$LOCKSMITHD_BIN" --config "$CONFIG"
```

The empty seed path prevents an installed seed catalog from being imported.
In another terminal, check the configured port:

```sh
curl --fail --silent --show-error http://127.0.0.1:9200/livez
curl --fail --silent --show-error http://127.0.0.1:9200/readyz
curl --fail --silent --show-error http://127.0.0.1:9200/version
```

Expect HTTP 200; `/version` reports the built crate version. `/readyz` describes
configured startup dependencies, not every agent's selected source. A ready
instance can still reject an individual unavailable binding with 503.

## Register, explicitly select, then call

Create a tool pointing to your local API. Export `UPSTREAM_URL` first:

<!-- smoke:catalog -->
```sh
"$LOCKSMITH_BIN" --socket "$SOCKET" --format json tool put "$REGISTRATION" \
  --upstream "$UPSTREAM_URL" --auth "$AUTH_SOURCE" --egress direct
```

For example set `REGISTRATION=accounts` and `AUTH_SOURCE=bearer=SMOKE_X`.
Set `AGENT_NAME=shared-a` and `ALLOWLIST=accounts` before registering:

<!-- smoke:register -->
```sh
"$LOCKSMITH_BIN" --socket "$SOCKET" --format json agent register \
  --name "$AGENT_NAME" --allowlist "$ALLOWLIST"
```

Save its returned `public_id` as `AGENT_ID` and its one-time `token` privately as
`LOCKSMITH_AGENT_TOKEN`. Do not send the operator token to the agent listener.
With `AUTH_SOURCE=bearer=SMOKE_X`, select the account:

<!-- smoke:bind -->
```sh
"$LOCKSMITH_BIN" --socket "$SOCKET" --format json agent set-credential \
  "$AGENT_ID" accounts --auth "$AUTH_SOURCE"
```

<!-- smoke:status -->
```sh
"$LOCKSMITH_BIN" --socket "$SOCKET" --format json status
```

```sh
curl --fail --silent --show-error \
  -H "Authorization: Bearer $LOCKSMITH_AGENT_TOKEN" \
  http://127.0.0.1:9200/api/accounts/check
```

The receiver's endpoint/path determines the useful response. It must observe
account X, never the caller token. Repeat registration/selection for `shared-b`
with `bearer=SMOKE_X` to share X, and `distinct-c` with `bearer=SMOKE_Y` to select Y.
Use `header=x-api-key:ENV_NAME` for a per-agent header selection. The catalog's
syntax differs: `header:x-api-key=ENV_NAME`.

## Clear, repair and inspect

<!-- smoke:clear -->
```sh
"$LOCKSMITH_BIN" --socket "$SOCKET" --format json agent unset-credential "$AGENT_ID" accounts
```

The next request is 403 `tool_not_allowed`, with no upstream operation. Re-run
`set-credential` to repair it. Missing/empty selected env values produce 503
`credential_unresolved`; missing/wrong/revoked caller identities produce 401.
Changing the catalog template does not repoint existing selections.

<!-- smoke:list -->
```sh
"$LOCKSMITH_BIN" --socket "$SOCKET" --format json agent credentials list "$AGENT_ID"
```

Reads show references and timestamps. Agent registration and bootstrap output
are intentional one-time credential deliveries; keep those private. See
[account troubleshooting](operator/account-binding-troubleshooting.md),
[explicit selections](concepts/per-agent-credentials.md) and the
[unversioned D1 change notes](changes/explicit-account-bindings.md).

## Stop and clean up

For this manual disposable instance, send SIGTERM/Control-C to its daemon and
wait for exit before deleting its private directory. Keep actual deployment
state and sealing keys under their normal backup policy. Use SQLite `.backup`
for databases with WAL; copying only `.db` can omit committed state. For an
existing installation follow the [reviewed migration](concepts/migrating-account-bindings.md)
and verify account attribution before reopening traffic.
