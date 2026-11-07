# Explicit native contract policy

Native connections use `finite-v1` unless an operator selects `finite-v2`.
This is the same review/grant/dispatch path for supported customer None, live
stored bearer, controlled OAuth and hosted OAuth accounts. Provider names,
URLs, metadata and hints never select the policy or grant authority.

For a manual registration, add the policy to the JSON passed to
`tool put --mcp-config-file`:

```json
{"protocol_version":"2025-11-25","contract_policy":"finite-v2","compact":true}
```

Preserve the connection's intentional destination settings. For an eligible
promoted local definition, use `tool activate-definition NAME --if-match REV
--contract-policy finite-v2 [--compact]`. An already promoted pin must first be
deliberately deactivated before changing policy. These configuration transitions
clear connection ACL/bootstrap authority, selections, observations, reviews and
grants. Restore the intended ACL/account selection, observe, review and grant;
use fresh sessions. Toggling back never revives an old grant.

Copy the exact fresh `source` and observation generation. A v2 source includes
`contract_policy:"finite-v2"`. The review request must also explicitly contain
`contract_policy:"finite-v2"`; mismatches refuse. The immutable contract stores
that marker and its digest covers it, the complete original provider tool,
effect, context and any input restriction. Unknown policies refuse. Saving a
review grants nothing. Follow [observe and grant](native-tool-review.md).

## Explicit customer catalog selection

An opted-in registration may also set `selected_tools` to 1–32 exact unique
upstream names. For example:

```json
{"protocol_version":"2025-11-25","contract_policy":"finite-v2","selected_tools":["invented_read","invented_empty"],"compact":true}
```

Definition activation uses repeatable `--selected-tool NAME` flags with the
same policy. The list is trusted configuration, not provider data. Observation
scans the entire bounded catalog (at most 256 names/four pages), checks every tool
for lossless SDK conversion and refuses duplicates even among omitted names.
All selected names must exist; their complete original schemas must pass the
chosen finite policy. An unsupported omitted schema is not invoked or granted.
The completed manifest contains `projection.policy:"explicit_registration_tools_v1"`
and exact `total`, `selected`, `omitted` counts. Nothing publishes early when the
selected names arrive. Selected contracts remain within 32 tools/48KiB.

No list means the ordinary full 32-tool catalog rule. Default v1 cannot select a
subset. Changes clear authority through the same registration repair path. Hosted
OAuth profiles retain their profile-selected names and provenance; a registration
list, if supplied too, must match the profile list exactly. Disagreement refuses;
there is no union, intersection or fallback. Generic selection does not adopt the
hosted SSE exception: ordinary response/notification/EOF behavior and deadlines
remain unchanged. Every mode retains its existing byte/event/aggregate limits.

## Finite additions

- `_meta` must be an object of at most 4096 serialized JSON bytes, depth 8
  (root depth zero), and 128 visited nodes. Object keys count as string nodes
  as well as their values; array elements and all scalar values count. Original
  values are preserved and screened against the held credential before storage.
  They are inert data: never follow metadata links or execute its instructions.
  The key `locksmith.dev/native-contract` is reserved for the public Locksmith
  projection and is refused in provider metadata. Other unknown tool fields
  still refuse.
- Input scalar defaults are validated annotations for string, integer, number,
  boolean or null. They must satisfy the finite type, length, range and enum/const
  constraints. Omitted arguments stay omitted, explicit arguments stay explicit,
  and required properties remain required. No object/array default is supported.
- Input scalar enums contain 1–64 distinct type-matched values. Membership is
  exact. Default v1 remains limited to 16. No truncation or coercion occurs.
- Only an input root with `type:"object"`, empty `properties`, and **absent**
  `additionalProperties` can use the explicit restriction below. Nonempty or
  nested open objects, `additionalProperties:true` and schema-valued openness
  remain unsupported.

All other finite grammar and wire limits remain unchanged. Output schemas still
use the existing v1 grammar and result checks. An absent output schema provides
no invented validation of business meaning. This policy changes no protocol,
request timeout, catalog selection count or account authorization.

## Empty arguments are an explicit restriction

For that exact open-empty input, the review request must include both:

```json
{"contract_policy":"finite-v2","input_restriction":"empty-arguments"}
```

These fields supplement the ordinary source/generation/name/digest/effect
request; they are not a complete request by themselves. The original tool is
retained unchanged in `contract.tool` with its original `observed_digest`.
`input_restriction` is part of the reviewed contract digest. The response also
returns `callable_input_schema`, even when fixed context is empty. This derived
schema adds `additionalProperties:false`; it describes what Locksmith will send,
not a claim that the provider declared a closed schema. Only `{}` is callable.
Any supplied key or fixed-context key refuses before a business request.

Standard `tools/list` presents the callable tool. Its `_meta` retains provider
metadata and adds `locksmith.dev/native-contract` with `policy`,
`contract_digest`, nullable `input_restriction` and `schema_origin` (`provider`
or `derived_callable`). Compact `describe` exposes the same marker as
`native_contract` alongside its callable `input_schema`. Fixed-context removal
also marks the schema as derived. Both facades use the same original review and
merged argument validation. The operator review retains the full original;
agent projections do not disclose operator-fixed values.

## Compatibility and evidence limits

Migration 0020 updates the definition activation guard to permit the explicit
policy and selected-tool fields, and clears them on deliberate deactivation.
It rewrites no registration, account, review or grant rows. Existing migration
checksums and sequence highwaters remain unchanged. Absent policy retains
historical v1 serialization. Prior schema-19 daemons refuse the newer database
before opening listeners; they must not reinterpret v2 as v1. Keep a consistent
backup before changing binaries. Current restart retains review bytes but requires fresh
observation. Rollback to old code is not a policy repair procedure.

Offline invented catalog and receiver tests establish the finite policy only.
They do not establish live shipping provider consent, full real catalog fit,
remote output meaning or release readiness. The earlier hosted workspace
`request_failed` has no proved cause; this correction does not attribute or
claim to fix it.
