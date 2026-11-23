# ADR-0005: Refuse unverified stored selections and backends on Slack routes

Status: Accepted

Date: 2026-11-23

## Context

F-018 corrects the credential bypasses found during review of F-002. Ingestion
verified a bearer value, but reference selection established only custody; backend
credential writes and activation had no workspace validation. A stored reference
can belong to a different route or workspace. No persisted verification proof
binds a backend key and its stashed bindings to this workspace and destination.

## Decision

Retain verified stdin/value ingestion. Refuse stored bearer and stored header
reference selections on workspace-declared routes with 400
`slack_workspace_selection_unsupported`. Check both ordinary and live-reference
selection under their `BEGIN IMMEDIATE` writer lock
(`src/repo/agent_creds.rs:48`). Refuse backend credential storage and all backend
switches under their own writer transaction with 409
`slack_workspace_backend_unsupported` (`src/registrations/backends.rs:294`,
`src/registrations/backends.rs:401`). This includes old persisted backend keys
and stashed bindings, regardless of whether they happen to match the workspace.
Refuse explicit stored references in route PUT as `invalid_metadata`
(`src/registrations/api.rs:680`). Keep-key broker edits retain the existing
transactional key/destination comparison. Custom-header ingestion remains refused.
[ADR-0002](0002-slack-workspace-ingestion.md) and the CLI reference inventory every
path. Environment, 1Password and OAuth exclusions remain unchanged.

## Consequences

A rejected selection preserves the prior binding. Backend refusals preserve keys,
bindings, stash, active destination and revision; nothing is inserted. Refusals
perform no provider call and contain fixed diagnostics only. Undeclared routes
keep existing behavior. There is no schema, listener or deployment change.
Operators must ingest bearer values rather than reuse references on declared
routes, and cannot switch those routes between backends.

## Alternatives considered

Decrypting references and checking each activation would require validating all
stashed bindings against the target destination and guarding every checked
snapshot against races. Persisted verification attestations require additional
ownership and invalidation rules. F-018 explicitly allows refusal; transactionally
refusing these paths is smaller and preserves the existing verified ingestion.
