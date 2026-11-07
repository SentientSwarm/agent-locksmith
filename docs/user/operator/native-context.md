# Fixed native context and safe diagnosis

Use the existing [connection setup](native-mcp.md) and
[observe, review and grant workflow](native-tool-review.md). A manual native
connection can use explicit None, a live sealed-bearer selection or
[owner-selected controlled OAuth](native-oauth.md) or
[hosted Linear](hosted-linear.md). Fixed context adds no account
authority. [Promoted customer pins](integration-definitions.md) use the same
path; native env/op/header accounts remain unsupported.

## Review a fixed value

Suppose an observed `read_record` tool requires string properties `workspace`
and `key`. Add an optional `context` object to the strict review request:

```json
{"source":{"instance":"FROM_GET","revision":1,"account_key":"FROM_GET","agent_epoch":1},"generation":"FROM_OBSERVE","name":"read_record","observed_digest":"FROM_OBSERVE","effect":"read","context":{"workspace":"reviewed-workspace"}}
```

Use the exact returned source, generation and observed digest:

```sh
locksmith --format json tool mcp review sample --agent AGENT_ID --file review.json > reviewed.json
```

The response retains the full original `contract.tool` and the fixed map, adds
`contract.context_profile: "fixed-top-level-v1"`, and returns the derived
`callable_input_schema` plus `contract_digest`. It still says
`prepared_only: true` and `callable: false`: saving a review grants nothing.
Deliberately select that digest with `agent mcp-grants replace`, using current
source, observation generation and grant revision as in the linked workflow.
An ordinary agent starts a fresh session, lists tools, then supplies only `key`.
Locksmith injects the fixed `workspace` and validates the full upstream input.

Context keys name existing top-level properties. A nested object/array is a
whole fixed value validated against that property's supported schema. There is
no dotted path, expression, file/URL retrieval or credential directive. A
URL-looking string stays data. Every protected property and its required entry
is omitted from the callable input schema; all-protected input becomes a closed
empty object. Output schemas and other supported constraints remain intact.
Any caller presence of a protected key refuses with `protected_argument`, even
an equal value, `null` or an escaped spelling. Nested fields with the same name
under an unprotected property remain ordinary input.

Omitted context and `{}` preserve old contract bytes/digests and response shape.
`null`, arrays, duplicate decoded members and unknown request fields refuse.
Invalid fixed values return `context_invalid`; oversized new contract/preview
returns `review_limit` before saving. Context and fully merged arguments each
obey32KiB,16-depth,4096-value limits; individually small halves can exceed the
merged limit. Nonempty stored contracts and whole review responses are also
limited to64KiB. Existing64KiB request and finite schema limits still apply.
Before saving, the combined full tool and context must also fit the same
32-depth/8192-structural-and-scalar-unit JSON parser used when loading grants.
A request can fit by itself while that combined contract returns `review_limit`;
the refusal leaves saved reviews and current grants unchanged.

## Nonsecret values and deliberate changes

Context is plaintext operator configuration, not secret custody. Do not put
credentials or sensitive data in it. Before saving a nonempty candidate,
Locksmith reads the current selected credential locally and screens decoded
keys/strings for that exact known secret; `context_secret` refuses before
persistence or response. Missing local custody refuses safely. It does not
contact an upstream to check credential validity. This is not general DLP.
The complete merged call is screened again using current selected custody
before DNS or upstream setup. Results retain the existing known-secret checks.

A new context value changes the digest but does not change existing grants.
Explicit replacement grants the new contract; old session pins refuse that
replacement. Open a fresh session and list again. Revocation, source changes,
observation freshness and drift still apply. Rotating a stored selection creates
a fresh reference and clears affected grants; re-observe, review and deliberately
regrant. Another agent still selecting the old live shared reference retains its
own authority. An old reference is never silently restored.

## Diagnose and repair

`tool mcp show` and `agent mcp-grants show` read local state without network I/O.
Their `diagnostics` object describes the current snapshot, not a historical
failure journal. `credential_readiness: not_checked` and
`provider_readiness: unverified` stay explicit. A saved review, selected grant,
fresh observation, active connection and session pin are different facts.

| State or error | Next step |
|---|---|
| `observation_required` | Inspect connection/account, then observe again; review changed tools and explicitly replace affected grants. |
| `ungranted` | Inspect the saved review and deliberately select its digest with current grant CAS. |
| `grant_current` | Open a fresh agent session and list; this does not prove provider credential validity. |
| `authority_unavailable` or activation/source error | Inspect enabled registration, current selection and runtime activation; correct the indicated configuration, then observe/review. |
| `source_conflict`, `observation_conflict`, `grant_conflict` | Read the current snapshot and rebuild the intended write; do not reuse stale preconditions. |
| `tools_list_required`, `tool_not_approved`, `authority_changed` | List in a current session or ask the operator to repair/regrant; connection ACL alone is insufficient. |
| `protected_argument`, `argument_schema`, `value_limit` | Construct only public arguments from the returned schema and respect merged limits. |

Query existing audit records with `locksmith audit query` (see its help).
`native_tool_denied` identifies controlled pre-admission refusals;
`native_tool_unknown` identifies submitted-COMMIT uncertainty. Confirmed
`mcp_admitted` records precede tool submission. `mcp_outcome` reports
`not_submitted`, checked `success`/`tool_error`, or `unknown`. Correlate the
server-generated `operation_id`/`admission_id`, not a caller request ID.
Records omit arguments, fixed context, raw provider/SQL errors and credentials.

An outcome or JSONL mirror may be missing. `native_diagnostic_unavailable` and
`native_operation_interrupted` are safe operational markers, not durable delivery
receipts. Missing outcome means unknown; it never authorizes replay. A checked
result survives later cleanup/diagnostic failure while its handler remains
owned; disconnected peers may never receive it. No remote rollback is implied.

## Upgrade and limits

Back up consistently before changing binaries, following the
[native upgrade procedure](../changes/native-mcp.md). The historical fixed-context
increment left schema 14 unchanged. Accepted pre-context B binaries could open
that schema 14 database and use empty contracts,
but reject context-bearing inventory, including the whole mixed tool set. Their
old review API refuses the new field; they can still deliberately replace/revoke
existing grant references. Every restart needs fresh observation. Re-upgrade
preserves exact stored reviews and revocation; it does not strip context or
restore grants. Current controlled OAuth adds schema 17 and prior whole-daemon
startup refusal; follow its [upgrade guidance](native-oauth.md#upgrade-and-evidence-limits). Use the current binary for context-bearing workloads.

Planned3.0.0 stays unchanged. This is a bounded local increment; full207/208,
live provider/customer readiness and release/publication remain separate. See
[implementation and verification](../../development/native-protected-context.md)
for diagnostic timing, synchronous filesystem limits and exact test entry points.

Current customer activation adds schema 18 and a whole-daemon prior refusal; see
[definition upgrade/recovery](../changes/integration-definitions.md). Earlier
schema 14/17 statements above describe their original increments.
