# Slack token metadata diagnostics

Inspect an owned attempt with
`locksmith oauth attempt-status slack ATTEMPT_ID` through the configured admin
socket. A token metadata refusal has `state: failed`, `stage: token` and one
fixed `safe_reason` below. It does not publish an account or proceed to identity
verification. Account inspection remains a separate supported command:
`locksmith oauth account-status slack --label account-x`.

The same decoder serves manual refresh. Its refusal uses the same closed code
in the error response and immediate refresh `safe_reason`. The reason is not
persisted in account metadata; losing the response leaves pending custody with
an unknown failure reason. Existing refresh
uncertainty and no-replay rules remain in force; a more precise reason does
not authorize another request.

## Closed vocabulary

Every name has prefix `slack_token_`. Append the field and suffix from this
table. No provider value, unexpected key, token, length or hash is included.

| Field | Response location | Refusal suffixes |
| --- | --- | --- |
| `issuer`, `iss`, `resource`, `client_id` | Optional root echo | `null`, `type`, `mismatch` |
| `team`, `authed_user` | Required object | `missing`, `null`, `type` |
| `team_id` | Required `team.id` | `missing`, `null`, `type`, `mismatch` |
| `authed_user_id` | Required `authed_user.id` | `missing`, `null`, `type`, `mismatch` |
| `authed_user_scope` | Required `authed_user.scope` | `missing`, `null`, `type`, `mismatch` |
| `root_scope`, `root_team_id`, `root_user_id` | Optional root echo | `null`, `type`, `mismatch` |
| `nested_access_token`, `nested_refresh_token`, `nested_expires_in`, `nested_token_type` | Optional `authed_user` echo of root field | `null`, `type`, `conflict` |

For example, `slack_token_authed_user_scope_missing` identifies an absent
required scope member; `slack_token_root_team_id_mismatch` identifies an
unequal optional root echo. Neither includes the expected or received value.
`type` means a non-null value of the wrong JSON type. Identity/echo/scope
fields require strings; parent containers require objects. Nested expiry
uses an unsigned integer type; other nested credential echoes use strings.

Checks retain their order: outcome; issuer/iss/resource/client echoes;
team, user and scopes; optional root scope/identity echoes; root credential
validation; then nested access/refresh/expiry/type echoes. Only the first
failure is reported. Multiple errors are not enumerated.

Nested credentials are equality echoes, never alternate token locations.
Absent nested members remain allowed. Equal root and nested null refresh or
expiry values remain allowed at initial exchange. A present nested null with
an absent root is a conflict reported with the `null` suffix. Explicit root
refresh null during manual refresh still returns `refresh_unavailable`.

Required fields, exact workspace/user/client bindings and the two scopes are
unchanged. Initial absent/null root refresh and expiry remain supported.
Malformed token fields still return `token_invalid`; duplicate keys or invalid
JSON return `json_refused`; token bodies over 65,536 bytes return
`token_body_limit`. Existing outcome, secret-screen and transport codes remain.
The [response schema](oauth-account-response-v1.schema.json) adds these codes
without removing old values. Consumers that enumerate reasons must accept the
additions. There is no database migration or custody rebind for this change.

Historical `token_metadata_mismatch` does not establish which predicate failed.
No new diagnostic can reconstruct an old response. Slack's
[documented response](https://docs.slack.dev/reference/methods/oauth.v2.user.access/)
shows the broad root-token, nested identity/scope and team shape; it is not
evidence of the contents of a particular exchange. Existing strict checks are
unchanged, and offline diagnostics do not establish live provider acceptance.

## Offline smoke

With the repository's [tested build profile](../../development/build-identity.md),
run `cargo test --lib oauth::consent::slack_tests -- --test-threads=1` and
`cargo test --test oauth_consent_process_test slack_metadata_ -- --test-threads=1`.
The latter uses invented local TLS responses and actual daemon/CLI status:
each metadata refusal has one token response, no identity/account/business
effect, and no plaintext canary in status, daemon log or fixture custody.
Duplicate, depth and body-limit controls retain closed refusals. Existing
`slack_optional_access_only`, `slack_refresh_nullable_persistence` and
`callback_issuer_` process controls cover positive and callback compatibility.
