# Offline definition contract v1

The [operator workflow](../user/operator/integration-definitions.md) is the
consumer entry point. This is the independent authoring portion of AGENT-203,
not completed live onboarding. Definition data is never executable authority.

## Strict input

One UTF-8 JSON object, at most65536 bytes, depth32 and8192 syntax units.
Duplicate object keys (including escaped-equivalent keys) reject before typed
decoding, through the shared native JSON parser. Unknown fields reject at every
level. Strings below are measured in UTF-8 bytes, nonempty after trimming, and
reject controls except LF/CR/tab. Arrays have unique values/IDs as indicated.

| Required field | Supported value or bound |
| --- | --- |
| schema_version | Integer1 |
| id | `local.` or `builtin.` plus nonempty suffix; at most64 ASCII lowercase letters/digits/dot/underscore/hyphen |
| revision | Integer1..2147483647 |
| name / summary / setup | At most128 /1024 /4096 bytes |
| protocol_profiles | Exactly `["mcp_streamable_http"]` |
| auth_profiles | 1..8 objects; unique profile IDs |
| workflows | 1..16 objects; unique workflow IDs |
| limits | 1..32 unique strings, at most1024 bytes each |
| verification | Required object below |

Auth profile: required `id` (same character/64-byte rule, no namespace required),
`mechanism` (`none`, `header`, `bearer`, `oauth_provider`), `setup` (4096 bytes),
`required_scopes` (0..32 unique strings of128 bytes). These are descriptions;
no header value, credential source, OAuth execution endpoint or secret field
exists. No profile is automatically converted to usable auth configuration.

Workflow: required `id`, `summary` (1024 bytes), `operations` (1..32 unique
strings of128 bytes), `effect` (`read`, `write`, `mixed`). Operations are labels,
not an executable plan, observed tool inventory or grant.

Verification: required `level`, `evidence_ref` (1024 bytes), `verified_at` and
`source_revision`. The latter two are **required nullable fields**, not optional.
`candidate` requires both null. `fixture` requires a valid Gregorian
`YYYY-MM-DD` date (years0001..9999) and7..64 hexadecimal revision characters.
`live` is unsupported pending accepted evidence contracts. Metadata is declared
by the operator; evidence references are never fetched or independently attested.

## Operator API and persistence

Existing operator authentication and UDS/HTTPS transport apply. New request
bodies require `Content-Type: application/json`, the64KiB cap and a10-second
body-read deadline. There is no new agent-facing authoring endpoint.

| Method/path under `/admin/operator` | Input / result |
| --- | --- |
| PUT `/integration-definitions/{id}/revisions/{revision}` | Definition matching path; first201, identical repeat200, conflict409 |
| GET same | Exact canonical definition/digest and truthful authoring status; absent404 |
| POST `/tools/{name}/from-definition` | Instance object below; new201, existing name409, unknown exact revision404, invalid400 |

```json
{
  "definition": {"id": "local.customer", "revision": 1},
  "auth_profile_id": "none",
  "upstream": "https://example.com/mcp",
  "allow_private_destination": false
}
```

Only `allow_private_destination` is optional (defaultfalse). Exact existing
profile membership and native tool/direct/HTTPS/self/private policy are required.
No account/grant/tool authority is inferred. Errors are static bounded envelopes
with codes `definition_invalid`, `definition_conflict`, `definition_not_found`,
`definition_unavailable`; existing writers use `definition_pending`.

Migration0012 adds immutable `integration_definitions(id,revision,canonical_json,
digest,created_at)`. Identity is fixed-field typed serde JSON serialization with
SHA256 over `locksmith-integration-v1` + NUL + canonical UTF-8 bytes. This is a
versioned local representation, not a general cross-language canonicalizer.
Object order/whitespace normalize; array order and values do not. A transaction
inserts or compares exact saved content without updating repeat rows/timestamps.
No deletion/update/latest/batch API exists. Builtin revisions must remain frozen;
future revisions require separate accepted documents, not replacement bytes.

Instances pin id/revision/digest/profile in typed `mcp.definition`. Missing pins
are omitted from serialization, preserving existing manual-native fingerprints.
The pin participates in full registration equality and0011 config invalidation.
An insertion trigger verifies stored definition/profile/digest and disabled,
operator-owned native/None shape; NULL/malformed pins fail closed. Updates of
pinned rows or adding pins by general UPDATE are refused. Deletion retains the
existing transactional name/authority cleanup. No second authority store exists.
Creation avoids runtime resolver refresh because a disabled row needs no activation.

Credential attachment now reads/rechecks the registration and writes sealed
custody plus auth attachment in one transaction. A concurrent pinned replacement
cannot leave an unattached sealed row after refusal; a failed attachment rolls
back both writes. This is a narrow extension of existing custody, not OAuth205
refresh durability or rollback of already submitted effects.

## Verification

```sh
cargo test --locked --test definition_validation_test --test definition_api_test
cargo test --locked --test definition_process_test -- --nocapture --test-threads=1
```

The process case uses the actual binaries, verified local TLS, operator CLI/UDS,
a separate Python TCP receiver, existing manual-native ping and HTTP setup,
strict invalid input, revision pinning, restart and authority snapshots. The
receiver must observe zero connections. The independent prior probe requires
preserved qualified public schema11 1de53fc binaries, with `LOCKSMITH_DEFINITION_PRIOR_DAEMON`
pointing to `locksmithd`, then the ignored case in `definition_process_test`.
It creates actual schema11 state, verifies authority preservation and zero
initial definitions on12, then prior refusal before either listener and restart.

Full locked root/crate checks and existing HTTP/native/Python/prior/adversarial
checks remain required at the candidate. QA/reviewer observations are separate
from builder evidence. Full203, live prerequisites, G0/G1 and broader release
acceptance remain pending; this stage does not authorize publication.
