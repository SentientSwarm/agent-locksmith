# Onboard an HTTP connection for an agent

An operator registers the service, reviews a named agent's finite grant and
selects its upstream account. The agent uses its own Locksmith bearer token;
it does not need an operator token, upstream credential or custody reference.
Locksmith proxies HTTP requests. Client construction and execution belong to
the agent runtime.

## Prepare the service and caller

Use [getting started](../getting-started.md) for a disposable daemon, operator
credential and the shipped reference account API. Its
[customer service example](../getting-started.md#configure-your-own-http-service)
uses the same workflow with an independent `GET /v2/jobs` service and custom
`x-customer-key` authentication. Supply an API you control for that example;
the reference API does not implement the customer endpoint.

For each connection choose:

- A stable registration name and `tool` or `model` kind.
- The HTTP(S) **base** URL, including any normal path prefix. For example,
  `https://service.example/v2` plus agent path `/api/jobs/items` forwards to
  `https://service.example/v2/items` when the registration is named `jobs`.
- An existing supported authentication source and egress mode (`direct` or
  `proxied`). Make the chosen source available to the daemon. Keep values in
  [credential custody](../concepts/per-agent-credentials.md), not URL text.
- The named agent, its complete intended registration allowlist and the
  explicit account selection for this connection. A registration's template
  alone authorizes no authenticated agent.

Operator `tool put` / `model put` and newly applied seed catalogs reject malformed
URLs, non-HTTP(S) schemes, URL userinfo, query strings and fragments. Localhost,
private hosts, IPv4/IPv6 and base path prefixes (including Codex's
`/backend-api/codex`) remain usable. Place request query parameters on each
agent request instead. This is syntax validation; it does not test DNS,
reachability, TLS or the selected credentials. Non-HTTP `infra` entries retain
their operator-only contract.

An invalid operator destination returns HTTP 400 `invalid_upstream` (CLI exit 1)
without echoing the submitted URL. It does not save or activate the change:
the existing row, grants and account selections remain intact. A malformed
destination anywhere in an applied seed catalog rejects that catalog before
any entry or seed version changes. Equal/older catalog versions still skip
application. Existing persisted registrations are not rewritten or migrated;
correct an invalid URL before its next operator update or newer seed apply.

Use the existing [registration and selection commands](../getting-started.md#register-explicitly-select-then-call).
For a new caller, register the connection before granting its name. For an
existing caller, inspect its current allowlist before `agent modify --allowlist`:
that option replaces the entire list. Preserve all intended names. Denylist,
expiry and revocation still apply. Even an authless upstream needs a deliberate
grant and explicit `--auth none` selection.

The supported contract is ordinary HTTP request/response, with existing streamed
response forwarding as described in the [wire contract](../agent-integration/wire-contract.md).
WebSocket, executable and protocol-plugin modes are unsupported. Unknown mode or
method/path grant fields are rejected by the operator API. Grants authorize a
whole registration; descriptions and examples cannot enforce narrower operations.
Do not represent a read-only description as a read-only permission.

## Publish a service description

After the reference/customer setup, publish an optional versioned public HTTP
description. The complete JSON metadata examples are
[reference](../../../examples/http-service-reference.json) and
[customer](../../../examples/http-service-customer.json). The reference describes
the actual `/check` text response; the customer describes JSON `/v2/jobs` with an
optional `limit` query parameter. Adapt only public service documentation and
examples; never include credentials or private custody/account labels.

Set `REPO_ROOT` to this checkout. Keep `UPSTREAM_URL`/`CUSTOMER_URL` identical to
the existing destinations and retain all intended other registration options.
These commands replace metadata and other PUT fields; they do not merge. If
you have private metadata, preserve it in your complete input file separately
from the public `http_service` member. Do not combine `--metadata-file` with
`--metadata key=value`.

<!-- smoke:service-descriptions -->
```sh
"$LOCKSMITH_BIN" --socket "$SOCKET" --format json tool put accounts \
  --upstream "$UPSTREAM_URL" --auth bearer=SMOKE_X --egress direct \
  --metadata-file "$REPO_ROOT/examples/http-service-reference.json"
"$LOCKSMITH_BIN" --socket "$SOCKET" --format json tool put customer-jobs \
  --upstream "$CUSTOMER_URL" --auth header:x-customer-key=SMOKE_Y --egress direct \
  --metadata-file "$REPO_ROOT/examples/http-service-customer.json"
```

An update that changes only metadata retains grants and account selections.
It still needs runtime activation; `active` never proves selected-source health.
Malformed descriptors return HTTP 400 `invalid_http_service` before writing;
seed entries receive the same prevalidation before any catalog row/version
changes. Legacy metadata without this member retains its previous behavior.
Only the validated descriptor appears in authenticated discovery; invalid old
members are omitted until repaired/removed, and other metadata is never projected.
See the [agent wire contract](../agent-integration/http-services.md) for versions,
types, limits, examples and the distinction between descriptions and grants.

## Inspect, hand off and verify

Retain the getting-started `LOCKSMITH_BIN`, `SOCKET` and `LOCKSMITH_OP_TOKEN`
settings. Set `REGISTRATION` to the connection name and `AGENT_ID` to the public
ID returned by enrollment. These are operator commands; outputs can include
private references and should stay out of the agent's handoff bundle.

<!-- smoke:connector-inspect -->
```sh
"$LOCKSMITH_BIN" --socket "$SOCKET" --format json tool get "$REGISTRATION"
"$LOCKSMITH_BIN" --socket "$SOCKET" --format json agent get "$AGENT_ID"
"$LOCKSMITH_BIN" --socket "$SOCKET" --format json agent credentials list "$AGENT_ID"
```

For a model, use `model get`. Confirm the intended destination, grant and
account reference separately. `activation: active` means persisted and runtime
configuration agree. `pending` means they do not; `disabled` denies use.
`credential_readiness: not_checked` is intentional: a saved selection or active
registration does not attest the chosen source's health. Instance `/readyz`
does not attest every agent account either.

Give the agent only its own token, Locksmith agent-listener base URL and the
public [agent integration guidance](../agent-integration/wire-contract.md).
Authenticated `/skill` and `/tools` show its eligible active connections;
`account_selected` describes selection metadata, not credential validity.
Keep operator credentials, environment-variable names, account labels and
provider values in the operator's separate setup context.

Perform a benign request and verify the **receiving service's** account identity
and operation count. Repeat with a missing grant or cleared selection: the
expected denial must add zero receiving requests or operations. An upstream
401 is not proof of zero dispatch. A missing/wrong Locksmith bearer must fail
before forwarding. Then restore only the intended grant/selection and verify
the expected account again. The reference and customer examples demonstrate
shared X/X and distinct Y selections without per-provider code.

## Repair and change deliberately

Follow [account troubleshooting](account-binding-troubleshooting.md) for exact
operator inspection, audit and repair commands. In particular:

- `403 tool_not_allowed` with audit `not_in_allowlist`: review the destination
  and replace the finite allowlist deliberately; selecting an account is not
  sufficient.
- `403 tool_not_allowed` with audit `account_binding_missing`: select the
  intended account. Do not fall back to the template or another agent's account.
- `503 credential_unresolved` or OAuth source errors: repair the selected
  source/session. An active registration can still have an unavailable account.
- `503 connection_not_active`: inspect and repair pending runtime activation.
  A write returning `connection_activation_failed` was saved but not activated;
  this differs from a rejected `invalid_upstream` write.

Changing upstream/egress or hard-deleting/recreating a name clears its grants and
selections. Review and approve both again. Disable/re-enable preserves choices;
deleting a seeded entry disables it. Clearing the account, removing the grant
or revoking the agent denies the next admission. Already-admitted requests can
finish; active stream cancellation is not promised.

This adds no schema migration or version bump. Existing unreviewed policies
still need the [reviewed grant/account cutover](../concepts/migrating-account-bindings.md).
Use isolated synthetic credentials for rehearsal; never put token deliveries,
secrets or database backups in reports. Stop disposable processes and remove
their temporary state when finished.
