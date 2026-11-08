# Run a standalone development instance

Locksmith authenticates a registered agent, checks its ACL, then uses that
agent's explicit account selection. Creating a catalog entry alone grants no
account access. Start with a disposable instance before upgrading a deployment.

For a customer native MCP service, follow the [complete operator-to-agent
journey](operator/customer-mcp-journey.md): import and promote a definition,
select an account, review and grant finite tools, then hand an ordinary agent
a semantic task. The HTTP development walkthrough below remains separate.

## Prerequisites and saved smoke

This flow was tested with Rust 1.94.0 and the committed `Cargo.lock`. Lower
toolchains have not been validated here; edition 2024 alone does not establish
the locked dependencies' minimum. Use a C toolchain, Bash and `sqlite3` on Unix.
The saved reference-service smoke and manual checks also use Python 3 and `curl`. Build from the repository root:

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

For a complete local example, start the shipped reference API in a separate
terminal from this checkout. It uses only Python's standard library, binds
loopback and accepts synthetic X/Y accounts. Keep it running:

```sh
export REPO_ROOT="$PWD"
export REFERENCE_PORT=9300
```

<!-- smoke:reference -->
```sh
exec python3 "$REPO_ROOT/examples/http-account-service.py" --port "$REFERENCE_PORT"
```

It prints its URL. In the daemon terminal, set:

```sh
export UPSTREAM_URL=http://127.0.0.1:9300
export SMOKE_X=synthetic-private-account-x
export SMOKE_Y=synthetic-private-account-y
```

These values belong only to this disposable example. Real deployments use their
normal secret custody. The env names in selections are references; Locksmith
reads their values in the daemon process. Keep the daemon terminal running; the
`exec` replaces its shell:

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

Use an absolute HTTP(S) base URL without userinfo, query or fragment. Localhost,
IP addresses and normal path prefixes are supported. Invalid destinations are
rejected before saving; existing grants and selections remain unchanged. See the
[operator onboarding recipe](operator/connector-onboarding.md) for validation,
inspection and the account/grant handoff.

<!-- smoke:catalog -->
```sh
"$LOCKSMITH_BIN" --socket "$SOCKET" --format json tool put "$REGISTRATION" \
  --upstream "$UPSTREAM_URL" --auth "$AUTH_SOURCE" --egress direct
```

For example set `REGISTRATION=accounts` and `AUTH_SOURCE=bearer=SMOKE_X`.
Set `AGENT_NAME=shared-a` and `ALLOWLIST=accounts` before registering:

Omitted grants authorize no connections. Register the connection first; choose
only current tool/model names. Later additions need a deliberate allowlist update
and explicit account selection, including authless connections.

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

The reference API returns `X`. Its `GET /counts` reports received requests
and accepted X/Y/NONE operations; the counts endpoint itself is not counted.
Use `curl http://127.0.0.1:9300/counts` before and after a denied request to
confirm both counts stay unchanged. An upstream 401 is not a zero-dispatch denial. Repeat registration/selection for `shared-b`
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
[explicit account binding notes](changes/explicit-account-bindings.md).

## Configure your own HTTP service

The same flow supports an ordinary service without provider-specific code.
For example, suppose your API serves `GET /v2/jobs`, authenticates
`x-customer-key`, and returns its own account identity. Set `CUSTOMER_URL` to
its base URL (no `/v2/jobs` suffix). Put its intended account credential in
`SMOKE_Y` in the daemon environment **before startup** (restart your disposable
daemon to change that environment). For a real deployment choose your own env
name and custody. The synthetic reference API above does not implement this
customer endpoint; use an API you control or implement that small contract.

<!-- smoke:customer-catalog -->
```sh
"$LOCKSMITH_BIN" --socket "$SOCKET" --format json tool put customer-jobs \
  --upstream "$CUSTOMER_URL" --auth header:x-customer-key=SMOKE_Y --egress direct
```

Choose `AGENT_ID` from the registered caller. Select its intended account:

<!-- smoke:customer-bind -->
```sh
"$LOCKSMITH_BIN" --socket "$SOCKET" --format json agent set-credential \
  "$AGENT_ID" customer-jobs --auth header=x-customer-key:SMOKE_Y
```

With the earlier `accounts`-only grant, a call is still 403. Read the generic
`GET /skill`, then the same endpoint with the agent's bearer for personalized
instructions. The operator can diagnose using
`locksmith --socket "$SOCKET" audit query --agent "$AGENT_ID" --tool customer-jobs`:
`not_in_allowlist` requires a deliberate grant. Inspect `agent get` first;
`modify --allowlist` replaces the whole list, so retain every intended existing
name. For this example the complete list is:

<!-- smoke:customer-grant -->
```sh
"$LOCKSMITH_BIN" --socket "$SOCKET" --format json agent modify "$AGENT_ID" \
  --allowlist accounts,customer-jobs
```

Set `LOCKSMITH_URL=http://127.0.0.1:9200` (or your chosen agent listener). Retry:

<!-- smoke:customer-call -->
```sh
curl --fail --silent --show-error \
  -H "Authorization: Bearer $LOCKSMITH_AGENT_TOKEN" \
  "$LOCKSMITH_URL/api/customer-jobs/v2/jobs"
```

Verify the receiving service identifies the selected account and receives one
operation. `GET /tools` and personalized `/skill` show current allowed, active
connections; `account_selected` is metadata, never a successful credential test.
Operator `tool get customer-jobs` distinguishes `activation: active` from
`pending` or `disabled`, and reports `credential_readiness: not_checked`.
A saved write with failed activation returns 503 `connection_activation_failed`
(CLI exit 1); inspect the saved entry, repair the catalog error, and retry the
intended write or restart normally. The affected connection stays denied while
pending; unrelated healthy entries can still work.

Changing upstream/egress or deleting/recreating a name clears its grants and
account selections. Review the new destination and explicitly grant/select
again. Disable/re-enable preserves choices. `tool delete` disables seeded entries
and hard-deletes operator-created entries. Removing a grant or account, or
revoking the agent, denies the next admission; requests already admitted can
finish. No active-stream cancellation is promised. See
[HTTP grant changes](changes/explicit-http-grants.md) and
[denial repair](operator/account-binding-troubleshooting.md).

## Stop and clean up

For this manual disposable instance, send SIGTERM/Control-C to its daemon and
wait for exit before deleting its private directory. Stop the separate reference
API with Control-C too. Keep actual deployment
state and sealing keys under their normal backup policy. Use SQLite `.backup`
for databases with WAL; copying only `.db` can omit committed state. For an
existing installation follow the [reviewed migration](concepts/migrating-account-bindings.md)
and verify account attribution before reopening traffic.
