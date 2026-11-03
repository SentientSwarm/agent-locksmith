# Explicit account admission (AGENT-176)

D1.1 uses the existing `agent_credential_overrides` row as an explicit account
binding. After authentication and the current ACL check, an absent binding
returns 403 `tool_not_allowed`. A selection-store error, corrupt AuthSpec, or
missing/empty selected header or bearer env value returns 503
`credential_unresolved`. None of these cases dispatches upstream. Repository
parse errors use a fixed classification so corrupt selection bytes cannot leak
through an operator read or error log.

An explicit `AuthSpec::None` remains an owner-approved credential-free selection,
subject to the current ACL. Clearing a binding denies the next admission;
replacing it changes the next admitted account. Explicit env bindings survive
registration credential-template edits. See [per-agent credentials](../user/concepts/per-agent-credentials.md)
for the existing operator commands and the changed clear/failure semantics.

## Coverage

`tests/explicit_account_bindings_test.rs` covers S01–S09 with actual bearer
authentication, SQLite repositories, catalog and forwarding. Only the external
upstream is simulated. Both header and bearer cases prove shared X/X and distinct
Y accounts at the receiver. Denials assert error class and zero upstream operations;
positive cases assert account and operation count. Sentinels are checked against
errors, audit/read data and captured proxy logs. Additional cases cover an
unwired selection repository and an unbound credential-free template.

`corrupt_binding_admin_read_never_echoes_stored_input` in the Phase J review suite
exercises the real operator list endpoint. Existing feature fixtures explicitly
select their intended sources while retaining the original injection, refresh,
header/body fixup, custody and ACL assertions. In the stored rotation fixture, an
old reference remains live while explicitly bound; the operator then explicitly
selects the rotated reference before its next upstream call.

The file-sealed integration now deliberately retires implicit startup-cache
injection. A real daemon with a registered agent first denies its unbound call
with zero upstream operations. The owner resolves the same chmod-0600 synthetic
file through `SecretResolver`/`FileSealedBackend`, imports its bytes through the
operator stored-source API and explicitly selects the returned stored-header
reference. The receiver still verifies the original header/account. Changing the
file does not change the imported snapshot; clearing the binding denies again.
Admin reads remain reference-only, and the missing-file degradation test remains.
Direct file-backed bindings are unsupported; later legacy diagnostics and
migration owner mapping remain separate work. No automatic import was added.

## Local diagnostic

The imported local-risk diagnostic now expects an unbound caller to be denied.
Its D4 scenarios retain explicit selections to isolate the existing ACL growth
and stale activation findings rather than masking them with D1 denials:

```sh
env -u LOCKSMITH_LOCAL_PROOF_MISSING \
  LOCKSMITH_LOCAL_PROOF_SELECTED=proof-selected \
  LOCKSMITH_LOCAL_PROOF_EMPTY= cargo run --example local_risk_proofs
```

Exit 1 still means at least one diagnostic contract fails; it is not a conformance
pass. The retained D4 findings are outside AGENT-176.

## Delivery boundary

This intermediate slice is not the complete D1 release. AGENT-177 owns additional
selected-source custody/OAuth validation and credentialed identityless legacy
enforcement; AGENT-178 owns reviewed migration; AGENT-179 owns actual operator
cutover and release acceptance. No production cutover or external provider calls
are established by these local checks. No version or changelog changes are made.

## Verification receipt

Local Darwin arm64, Rust/Cargo 1.94.0, base `5d606d5` (2.8.0):

- Baseline `cargo test --all`: exit 0, 559 reported passes.
- Initial D1 regression run on the baseline: 9 failed zero-dispatch assertions,
  5 passed. The same cases pass after enforcement; the final admission suite
  contains 17 passing cases, with the corruption-admin check passing separately.
- Final `env -u OPENAI_API_KEY -u ANTHROPIC_API_KEY cargo test --all`: exit 0,
  577 reported passes, no failures or ignored tests. Two optional cloud tests
  return early without keys; no live-provider coverage is claimed.
- `cargo build --bins`, `cargo clippy --all-targets -- -D warnings`, and
  `cargo fmt --check`: exit 0 each. This is a debug build, not release acceptance.
- Diagnostic command above: exit 1, 23 observations, 21 matching expectations and
  exactly the two retained D4 findings (public ACL expansion and stale activation).

Two mTLS listener startup timeouts occurred during concurrent compilation/check
load in an earlier full run. The isolated rerun and final serial full run pass;
no timeout or assertion was relaxed. The legacy file success fixture was updated
under the explicit snapshot-import scope ruling described above, not concealed
as an allowed implicit-cache dispatch.
