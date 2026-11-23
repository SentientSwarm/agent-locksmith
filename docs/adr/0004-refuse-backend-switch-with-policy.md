# ADR-0004: Refuse backend switching while method policies exist

Status: Accepted  
Date: 2026-11-23

## Context

F-017 corrects the policy loss found in review of agent-locksmith#172.
`BackendRepository::switch` stashes credentials, deletes active bindings and
restores destination bindings. Migration 0028 cascades policy deletion with its
binding, but `backend_bindings` has no policy storage. A round trip can therefore
restore a formerly restricted credential without its policy.

## Decision

Refuse a switch with 409 `backend_method_policy_present` whenever any binding on
the route has a policy, including an empty policy. Check inside the existing
`BEGIN IMMEDIATE` switch transaction before the first write
(`src/registrations/backends.rs:438`). Policy writes also use `BEGIN IMMEDIATE`
(`src/repo/agent_creds.rs:166`), serializing policy creation and the switch.
The refusal changes no backend, binding, policy, stash or revision. Keep all
existing switch behavior for routes without policies.

## Consequences

An A to B to A attempt cannot silently discard a policy. Operators must explicitly
remove every policy before switching, then configure the intended restrictions
on destination bindings. Clearing policies removes method restrictions, so the
refusal itself never does that on the operator's behalf. No migration or new
policy ownership model is needed. Admission and credential custody are unchanged.
The real-daemon regression is
`qa/smoke/test_rte_backends.py::test_switch_refuses_binding_method_policy`.

## Alternatives considered

Stashing policies alongside each backend's credentials would allow transparent
round trips, but requires a schema and lifecycle changes for stash invalidation,
credential deletion and restoration. F-017 explicitly permits refusal; choosing
it keeps existing policy ownership and fails closed with a smaller change.
A handler-only check could race with policy writes, so the repository owns it.
