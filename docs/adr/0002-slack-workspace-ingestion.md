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
