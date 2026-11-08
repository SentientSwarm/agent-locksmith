# Native operator preparation (AGENT-206A)

[Operator workflow and API](../user/operator/native-tool-review.md) describes the
consumer surface. Stage A prepared authority; [stage B dispatch](native-dispatch.md)
now consumes its exact current intersection. [Fixed context](native-protected-context.md)
extends the immutable review. Full206/provider/compact gates remain separate.

`src/native_authority/` reuses registration admission, full catalog activation,
explicit agent selections, the sealed credential store, SQLite and the accepted
bounded client. It does not create a second authentication/account system.
Current finite ACL minus denylist and agent lifecycle apply even to an
operator's selected observation subject. `source` captures instance/revision,
account digest and agent authority epoch; all mutation paths recheck inside the
transaction that writes prepared state. Durable grants are not epoch-keyed.

Migration0014 creates empty observation, immutable review and finite grant-set
state. Opaque random128-bit generation/revision values prevent reset ABA. An
observation reserves its generation before I/O; final publication/failure is
conditional on that generation. Complete publication atomically removes grants
for changed/removed observed digests and advances affected set revisions.
Unchanged tools survive unrelated drift. Selection removal/replacement clears
only its agent/connection grants; config/destination changes clear connection
preparation. Registration-instance cascades prevent name reuse. Metadata
revision and process run identity are included in freshness. A successful old
response cannot refresh current authority; a late old failure cannot poison it.

The observed digest covers the entire supported tool under
`locksmith-native-tool-v1`; the reviewed digest covers
`{tool,context:{},effect,retry:"never"}` under `locksmith-native-contract-v1`.
Domain bytes, NUL separator and recursively key-sorted JSON feed SHA-256.
Nonempty fixed context adds its map/profile to the same domain; the full tool
remains stored. Empty/omitted context preserves these bytes.
Arrays and pinned serde_json number representation remain significant. This is
not RFC8785/cross-language numeric equivalence. Repeat reviews are immutable
no-ops. Grant replacement is all-or-nothing and checks every exact review
against the current complete observation, source and expected set revision.

## Default finite-v1 vocabulary

Tool members: `name`, optional `title`/`description`, `inputSchema`, optional
`outputSchema`/`annotations`. Names are1–128 UTF-8 bytes without controls;
titles at most128 and descriptions at most2048 bytes. Annotations permit only
`title` and boolean `readOnlyHint`, `destructiveHint`, `idempotentHint`,
`openWorldHint`. Provider hints never substitute for declared effect.
`icons`, `_meta`, execution/task extensions and other members refuse v1 observation.
An explicit [finite-v2 policy](../user/operator/native-contract-policy.md) adds bounded
metadata, scalar input defaults/enums and a separately reviewed empty-input
restriction. Output schemas keep v1. Policy is persisted in McpConfig and Source,
required in review, stored in the same immutable contract and rechecked against
current source during grant/effective/dispatch. No second authority store exists.

Input/output roots must be objects. Nested schemas permit a single explicit
`type`: object/array/string/integer/number/boolean/null. All objects require
`properties` and `additionalProperties:false`; optional `required` contains
unique existing property names. Arrays require one `items` schema. Optional
`title`/`description`, scalar type-matched `const` or `enum` (not both;1–16 unique
values), and exact2020-12 `$schema` are accepted. Type-appropriate min/maxLength,
min/maxItems, minimum/maximum must have valid numeric types/order. Ordering
preserves parsed64-bit integers, including when compared with floating bounds;
it does not round integer bounds through floating-point conversion. Depth is8 and
schema nodes128. Every other keyword is unsupported, including refs, regex,
formats, composition, conditional and remote/file retrieval. This grammar also bounds the stage B argument/output-schema evaluator.

Raw JSON and every SSE data message pass duplicate-member parsing and the
supported response validator before SDK conversion. Unknown tool/schema members
cannot disappear during SDK normalization and become reviewed input. The
existing native ingress uses the same duplicate parser with its own limits.
Semantic screening rejects selected bearer substrings in decoded keys/strings,
including quotes/backslashes hidden by JSON escaping. Refusal diagnostics are
static and SDK payload tracing remains filtered; no general DLP claim.

## Wire, connection and ownership

The accepted `StreamableHttpClient` hook performs initialize, initialized,
at most four sequential list pages and best-effort DELETE. Caller checks IDs,
result kinds, protocol and session consistency; no SDK worker/GET/retry is
started. Operator observation cannot call tools; stage B uses a separate final
admission transaction before one call through the same bounded hook. Every approved DNS answer is pinned
to the exact endpoint's resolver with no fallback. The caller validates actual
addresses; literal IPs must match the pinned set. TLS verifies normal hostname
and system/additional roots. Daemon startup installs its existing Rustls crypto
provider even with only plain bearer/UDS listeners; outbound TLS does not depend
on an inbound TLS listener. An already-installed provider is preserved.
[IANA IPv4](https://www.iana.org/assignments/iana-ipv4-special-registry/)
and [IPv6](https://www.iana.org/assignments/iana-ipv6-special-registry/) special
ranges inform the deliberately restricted address policy; special translation,
protocol-assignment and documentation ranges are not general provider endpoints.

Local interface addresses come from read-only `getifaddrs`; actual bind results
populate the shared listener registry before observations are eligible. Same
numeric port on a different approved address is permitted. No route/Serve or
trust-store mutation, arbitrary external alias discovery or local service
inventory is performed.

The205 operation-owner gate tracks preparation futures too. Its atomic
close/register gate covers slot admission, source/DB waits, DNS/network,
materialization, cleanup and publication. One shared8-slot runtime serves UDS
and HTTPS. Closing drops owned futures and permits before daemon return releases
the state lock, including startup errors and forced drain. No detached cleanup
or SDK worker exists. Already-submitted SQL/remote work and platform resolver
work may finish independently; cancellation is not rollback. A conditional
COMMIT already submitted retains that uncertainty.

Per-attempt aggregate byte admission is shared across client clones; every
response body contributes, including errors. The first transport chunk/parser
allocation and OS/TLS buffering are not process heap guarantees. The48KiB limit
covers the complete `{tools:[{tool,observed_digest},...]}` manifest envelope.
10s operation lifetime does not reset per page; it follows a separate10s bounded
body read. Operator authentication before the handler is outside those deadlines.

## Checks and attribution

Focused target: `cargo test --locked --test native_preparation_test`.
Actual daemon/CLI/separate verified-TLS receiver:
`cargo test --locked --test native_preparation_process_test`.
Per-agent stored write cases also live in `agent_stored_override_test`.
The process target retains actual old/new-generation success/failure races,
binding ABA during network wait, shutdown/restart, one operation deadline,
assigned-port0 self refusal and complete JSON/SSE manifest boundaries.
Its ignored schema13 probe requires `LOCKSMITH_PREPARATION_PRIOR_DAEMON` pointing
to an independently preserved public3e86ff8 daemon with its matching CLI sibling. It checks existing HTTP
receiving effects, sealed bytes, zero new authority and prior refusal. This
probe never downloads or rebuilds a prior binary implicitly.
Run the root full suite, strict all-target Clippy/fmt/binaries and the separate
transport crate suites. Saved HTTP/native/definition/OAuth recovery process
checks and prior-binary probes remain required; new migration has no authority.

The original nested-duplicate transport assertion fails before the parser
correction and passes afterward. Builder draft logs, immutable exact-candidate
checks and independent public-consumer QA/reviewer results are separate evidence.
No production provider, model, owner consent, installed service or release asset
is exercised by these disposable local tests.

## Public receiving and API staging

This ships in 3.0.0 and keeps all existing OAuth uncertainty/owner,
HTTP/CAS/definition and native deadline behavior. Historical local Stage A
acceptance is not a current runtime result.
The schema 13 CI gate pins public `3e86ff8a9b1a2c0d08faab83dcd48248baef3b98`,
builds/copies both matching binaries before the current target is overwritten,
and runs the separate ignored upgrade probe with LOCKSMITH_PREPARATION_PRIOR_DAEMON.
The four earlier probes retain their own distinct binaries and environments.

The operator guide defines the implemented staged API. Draft discover/account_ref,
per-tool review-path and HTTP If-Match sketches are not implemented routes or an
OpenAPI parity claim. Existing subject-agent selection and strict body-carried
source/generation/revision predicates define this preparation interface.

## Request body ownership

After operator authentication, every preparation write registers with the same
RefreshOwner before buffering. Body64KiB/10s and later operation8slots/10s remain
separate: waiting for a body uses no operation permit. Nested operation admission
shares the close/register gate; neither scope waits for itself. Shutdown cancels
and waits for owned body/operation futures before daemon return/state-lock release.
This does not join every HTTP connection/authentication task or roll back submitted
SQL, OS-resolver or remote work. Test-only body-drop/forced-listener probes qualify
instrumented library wiring; shipping binaries have no probe/header behavior.
Actual behavioral receiving remains required; source presence is not runtime proof.
