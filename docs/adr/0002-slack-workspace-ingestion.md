# ADR-0002: Check Slack workspace before sealing a token

Status: Accepted

Date: 2026-11-23

## Context

AGENT-340 requires a route to reject a token from another Slack workspace, including
on replacement. Identity remains binding-owned. Existing routes ingest credentials
offline, and deployments already define egress enforcement and route-specific CA
trust. Neither provider bodies nor credential values are safe diagnostics.

## Decision

Declare an optional `metadata.slack_team_id` on an HTTP tool. The CLI exposes
`--slack-team-id`; no database migration or new listener is needed. Make the
expectation immutable under registration upserts, including concurrent writes
(`src/registrations/repo.rs:267`). Operators create a new route to change it.

Before route or per-agent sealed bearer ingestion, request `POST auth.test` from
the declared upstream through the existing client builder. Honor its egress and
CA policy, disable redirects and retries, and limit the exchange to five seconds
and 16 KiB (`src/registrations/slack_workspace.rs:88`). Require `ok:true` and an
exact, valid team id. Error messages contain fixed text and validated ids only.

Do network I/O before the write transaction, then compare the route snapshot
inside that transaction before storing anything. Route ingestion already has
this comparison (`src/registrations/credential.rs:39`); per-agent ingestion now
has it too (`src/admin/stored_credential.rs:187`). Failed verification neither
inserts a sealed value nor replaces the existing key.

F-018 closes unchecked attachment paths by refusal, as recorded in
[ADR-0005](0005-slack-unverified-credential-paths.md). The path inventory is:

| Credential path on a declared route | Result |
|---|---|
| `tool set-key` / route credential PUT, bearer value | `auth.test` before storage; replacement repeats the check |
| `agent set-credential --stored-bearer-stdin` / binding credential-value PUT | `auth.test` before storage; transaction compares route snapshot |
| `agent set-credential --stored-bearer-ref` / `StoredBearer{secret_ref}` selection (including live-reference mode) | 400 `slack_workspace_selection_unsupported`; a live reference is not workspace proof |
| `StoredHeader` reference selection | 400 `slack_workspace_selection_unsupported` |
| Custom-header value ingestion, explicit or inherited | Refused; only bearer values can be verified for this contract |
| Explicit stored auth in route PUT | 400 `invalid_metadata`; use `tool set-key`. A broker edit omitting auth may retain its existing checked key only with unchanged destination and a transactional key comparison |
| `route backend set-credential` / `PUT /admin/operator/routes/{route}/backends/{backend}/credential` | 409 `slack_workspace_backend_unsupported`; nothing stored |
| `route switch` / switch API | 409 `slack_workspace_backend_unsupported`, including preexisting backend keys or bindings; no activation or revision change |
| Environment, 1Password and OAuth references | Existing exclusions unchanged; no new workspace check |

Backend declarations may still be managed, but cannot be activated on a declared
route. Reference selections and backend operations refuse locally without an
`auth.test` call. Use the value-ingestion paths to install or rotate a verified
bearer. Routes without `slack_team_id` keep every path's existing behavior.

## Consequences

Declared routes depend on Slack availability for token ingestion, but ordinary
proxy requests gain no new network exchange. Unconfigured routes retain offline
behavior. A concurrent route edit may require an operator to repeat the write.
Custom-header keys are refused on declared routes. Existing broker routes still
accept only broker selections; this change does not remove that restriction.

The check covers sealed values, not externally resolved env/1Password credentials
or OAuth. An operator still controls the upstream destination; this declaration
is not an allowlist of trusted Slack servers. No production configuration changes
are part of this implementation.

## Alternatives considered

A request-time check adds Slack latency and availability dependence to every call.
A mutable team declaration could invalidate keys already accepted on the route.
Holding a SQLite write lock during the network exchange blocks unrelated admin
writes. A separate policy table adds schema and joins for one route-owned string;
the existing metadata contract is sufficient here.
