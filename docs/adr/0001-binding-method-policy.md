# ADR-0001: Keep upstream method policy with the binding

Status: Accepted  
Date: 2026-11-23

## Context

A route grant and explicit credential selection admit every upstream method.
The same Slack route serves identities whose allowed methods differ. A route-wide
policy cannot represent that difference. AGENT-339 requires live policy changes
without altering credential custody or the default behavior of existing bindings.

## Decision

Store an optional allow/deny method policy in SQLite, owned by the explicit
agent/registration binding (`migrations/0028_binding_method_policy.sql:2`). A
foreign key deletes it when its binding disappears. Credential replacement
preserves it. The operator API replaces or clears the policy without a restart.

A backend switch refuses routes with any binding method policy (409
`backend_method_policy_present`), before mutation and in the same `BEGIN
IMMEDIATE` transaction that would stash/delete/restore bindings
(`src/registrations/backends.rs:438`). Policy writes use the same transaction
mode, so none can race between this check and binding deletion. The existing
backend stash holds credentials only: deleting the active binding would cascade
away its policy and restore unrestricted access on the return leg. F-017 chooses
explicit refusal instead of extending that stash. See
[ADR-0004](0004-refuse-backend-switch-with-policy.md).

Read it with the binding and grants in the admission snapshot
(`src/registrations/admission.rs:64`). Reject unmatched, denied or nonliteral
method segments before resolving credentials or dispatching upstream
(`src/proxy/admission.rs:70`). Deny wins; absent policy permits every method.
Pattern parsing is bounded and deliberately excludes general globs and regexes
(`src/method_policy.rs:6`). Persisted invalid policies fail admission closed.

## Consequences

Permissions differ per identity while credential ownership remains unchanged.
Every newly admitted request sees committed policy state; already admitted work
may finish. The API is for Slack-style method endpoints, not general REST paths.
Percent-encoded methods and path separators are refused under a policy to avoid
upstream decoding differences. Operator changes and refusals are audited without
credentials. Operators should clear a policy deliberately when repurposing a route.
Operators who need a backend switch must explicitly clear all binding policies
on that route first and reapply the desired policies to destination bindings.

## Alternatives considered

A route-wide policy cannot distinguish identities. Embedding policy in AuthSpec
would couple authorization to credential replacement. A separate cached policy
read could disagree with the binding snapshot; joining persisted state avoids it.
