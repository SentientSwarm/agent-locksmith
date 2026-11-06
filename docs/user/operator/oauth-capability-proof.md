# Bounded OAuth refusal and lifecycle evidence

These tools prepare a separate, explicitly authorized proof. They do not authorize
consent, account access, refresh, native calls or publication. Keep an existing
positive account sealed and unselected unless its owner explicitly selects it.
An offline fixture is not evidence of a hosted provider's behavior.

## Closed token refusal reasons

Declared `custom-oauth-v1` contracts retain every existing acceptance predicate.
A strictly decoded token response containing only `error:"bad_code_verifier"`
and optionally `ok:false` produces `token_verifier_refused` at the token stage.
This applies to HTTP 200 and HTTP 400 exchange refusals. It never means success.
An extra field, description, URI, known-secret contamination, unknown error,
`invalid_code` or `invalid_grant` gives no specific verifier attribution.
Duplicate, malformed and oversized bodies remain refused by the existing bounds.
No response value, body, value hash or length is returned in the diagnostic.
Identity diagnostics remain separate. Manual refresh's HTTP 400 `invalid_grant`
retains `refresh_invalid_grant`, consumed pending state and no automatic replay.

`oauth attempt-status REGISTRATION ATTEMPT` returns stored closed `safe_reason`.
A refresh reason is in its immediate response; a lost response can remain pending
or UNKNOWN. A generic refusal cannot establish S256 enforcement. Historical live
failures cannot be retrospectively assigned these newer categories.

## One challenge-only transformation

The stdlib helper accepts a private JSON receipt and creates a different private
receipt. It never connects to a provider, reads a daemon key or extracts a verifier:

```sh
python3 scripts/oauth-challenge.py --input PRIVATE_INPUT --output PRIVATE_OUTPUT
```

Both files' parent must be a real same-owner directory with mode 0700. Input must
be a same-owner regular 0600 file. Output is exclusive 0600 and must not exist.
Success stdout is only `{"state":"challenge_changed"}`. Refusal stdout is only
`{"state":"refused","reason":"authorization_challenge_refused"}` with exit 1.
Neither stdout nor errors contain the URL. The output object is `{"url":"..."}`
and must remain private. Do not paste it into reports, arguments or messages.

Input is exactly `{"url":"...","expected":{...}}`. The trusted `expected` object
has seven nonempty string keys: `authorization_endpoint`, `client_id`,
`redirect_uri`, `scope`, `resource`, `state`, `code_challenge`. Endpoint/client/
redirect/scope/resource come independently from the approved profile and launch
packet. State and challenge come from the same fresh, supported normal connect
receipt. Keep profile ID/digest, client generation, source/account and finite authorization
bindings in the separate trusted launch packet. Never populate the expected
object by trusting an arbitrary input URL.
The closed URL has exactly these query fields plus `response_type=code` and
`code_challenge_method=S256`. Unknown, blank, decoded control characters or duplicate fields refuse.
Malformed or excessively nested private JSON returns the same closed refusal.
The helper compares the exact trusted scope serialization, including declared
space or comma separators; it does not normalize either representation.

Only the raw value span of `code_challenge` changes. All other bytes, including
query order, escaping, state and callback, stay identical. The replacement is a
distinct canonical 43-character S256 challenge from an independent fresh random
verifier. No daemon verifier override or credential import is supported.

Under a future finite authorization, use a fresh separate negative label and
normal connect. Keep it operationally isolated: no agent selection, grants,
review or tool calls. A completed exchange must send the original sealed verifier
exactly once. A specific refusal, no identity request and absent negative account
are required receiving evidence. Unexpected success is honestly a connected
unbound account, never an enforcement PASS; do not select it. Stop and request
owner disposition through the normal supported lifecycle. No automatic retry,
refresh, second consent or cleanup provider call is implied.

## Lifecycle and useful read prerequisites

Supported state inspection precedes each CAS mutation. Use the exact observed
revision for manual refresh, account disconnect and agent selection; stale
revisions must refuse without provider effects. Reopening the same normal store
with the same keys preserves sealed custody and verified typed subject. Restart
is not fresh consent, selection, review or grant authority. A reconnect is a new
account generation and requires explicit fresh selection/review as applicable.
User/workspace and service-principal subjects remain distinct, observed identity
must match exact policy, and every exchange/refresh must supply exact scope
evidence. Invented refresh capability says nothing about a retained account
whose refresh token is absent. Cancelling a pending attempt prevents late callback
exchange/publication. Disconnecting prevents subsequent native admission.

For a later finite useful read, first obtain the exact current observed tool
names, complete supported schema, source binding and digest. Apply explicit
operator selection, effect review and finite grants. Read only the already chosen
workspace/channel/thread under those observed schemas; do not guess hosted tool
names or arguments from fixtures. Retain actual receiving effects and session
DELETE attempts within the authorized total send/deadline bound. Post-submit
failure may be UNKNOWN. A useful read, lifecycle proof and complete S256 proof
are separate claims. Fixed external custody end remains authoritative; these
commands do not reset it or implement a product TTL.
