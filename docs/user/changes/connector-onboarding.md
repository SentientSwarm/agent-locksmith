# HTTP connector onboarding (3.0.0)

These changes ship in 3.0.0. The major-release compatibility rationale below
applies. Commands below are reproduction instructions.

An operator configures a reference or customer HTTP service, approves a named
agent's finite grant and selects its upstream account. The agent constructs
calls from authenticated discovery using only the Locksmith base URL and its own
token. Locksmith mediates calls; the agent runtime owns client execution and
tool installation.

## What changes

- [Operator onboarding](../operator/connector-onboarding.md) connects registration,
  account selection, grants, receiving-account verification and deliberate repair.
  HTTP destinations are validated before a write or seed apply changes state.
- Optional `metadata.http_service` version 1 describes ordinary request/response
  operations: method, literal relative path, query, JSON body, JSON/text response,
  errors and public examples. Operators publish nested metadata with
  `--metadata-file`. Only the validated descriptor appears in JSON discovery.
- [Agent guidance](../agent-integration/http-services.md) explains client
  construction without upstream credentials or private setup knowledge. The
  reference `/check` returns text; the customer `/v2/jobs` example returns JSON.
- Personalized `/skill` retains catalog-backed agreement with `/tools`, correctly
  identifies authenticated output and does not invent a chat operation for an
  arbitrary service. Rendered audit guidance covers security 403 and proxy 503
  diagnosis before the operator deliberately repairs authority or source.

Descriptions do not grant access or enforce operation-level restrictions.
Whole-registration grants and explicit account selection remain independent.
Metadata-only updates preserve both but still require runtime activation.
`active`, `account_selected` and `credential_readiness: not_checked` describe
different facts; an active route or selected reference does not prove health.

## Compatibility and upgrade

These changes are included in the **planned, unshipped 3.0.0**. Optional discovery
metadata and its CLI input are additive. Stricter destination and descriptor
validation reject some previously accepted writes, so this is not an entirely
backward-compatible refresh. The already planned major release also includes
the [explicit-grant/account cutover](explicit-http-grants.md). There is no extra
per-issue version bump, new schema migration or automatic rewrite for onboarding.

1. Complete the existing [reviewed grant/account migration](../concepts/migrating-account-bindings.md)
   if upgrading from implicit access. A descriptor does not migrate policy or
   grant an old bootstrap scope.
2. Review HTTP tool/model destinations before their next update or newer seed
   apply. Use absolute HTTP(S) base URLs without userinfo, query or fragment.
   Localhost, private hosts, IP literals and normal base paths remain supported.
   Non-HTTP infra behavior is unchanged. Move queries to individual requests;
   keep credentials in the selected custody source, never in a URL.
3. Existing registrations without `http_service` remain usable. If adding it,
   follow the [versioned contract](../agent-integration/http-services.md#version-1).
   Malformed old members are omitted from discovery; repair or remove one before
   updating that registration. Invalid new members fail before state changes.
4. Supply a complete metadata JSON value with `--metadata-file`; it replaces,
   rather than merges, metadata. Preserve intended private neighbors and other
   PUT fields. Do not combine it with `--metadata key=value`. Keep the destination
   unchanged for a metadata-only edit: destination replacement clears old grants
   and selections and requires deliberate reapproval.
5. Re-fetch authenticated `/skill` and `/tools`, construct a benign request from
   discovery, and confirm the receiving account. A cleared selection or removed
   grant must deny with zero receiving arrivals. Diagnose from
   [safe operator guidance](../operator/account-binding-troubleshooting.md) and
   restore only the intended choice. Never retry another account automatically.

No automatic scan retroactively rejects stored destinations. Invalid destinations
or descriptors are refused before an operator write or applied seed changes
rows/version. A saved activation failure is different and can leave the updated
registration pending; inspect state before retrying.

## Verification and independent consumer evidence

The [saved smoke](../../development/explicit-account-bindings-smoke.md) uses
disposable actual daemon/CLI processes, SQLite, loopback ports and synthetic
accounts. It executes shipped setup/publication commands, typed-discovery calls,
X/X/Y and customer attribution, zero-dispatch denials, rendered diagnosis and
deliberate repair, activation/lifecycle changes, restart and cleanup.

```sh
cargo build --locked --bins
cargo test --locked --test explicit_binding_smoke_test -- --nocapture
cargo test --locked --all
cargo clippy --locked --all-targets -- -D warnings
cargo fmt --check
```

Independent checkpoint evidence is separate from that scripted smoke:

| Revision | Actual independent result |
| --- | --- |
| `d478bb3` | Operator docs journey and destination/authority preservation accepted by QA and reviewer. |
| `5cbaf4c` | QA constructed an original client from public docs and authenticated discovery; reference text and customer JSON calls succeeded with denial/repair checks. Reviewer independently validated source and selected regressions. |
| `5cdca39` | QA reused its unchanged client and verified both runtime guidance corrections, catalog isolation and rendered diagnosis/repair. Reviewer independently executed the affected process paths. |

These bounded checkpoints do not substitute for final-revision acceptance.
Final delivery records the immutable revision, commands/exits, fresh ordinary
identity and allowed input bundle, preserved consumer code/repair history, full
gates and separate QA/reviewer verdicts. Consumer work precedes private source
or test inspection. Operator setup and receiving evidence stay outside consumer
inputs. This uses the existing QA seat with declared input separation; it is
not a fresh-model-context or filesystem-isolation claim.

## Limits and release state

Local synthetic services do not establish live provider, installed deployment,
Kamiwaza/Tomo or cross-platform compatibility. There is no new federation,
quota/pool system, executable plugin host, WebSocket or protocol adapter.
Version 1 is a bounded descriptive contract, not JSON Schema or runtime payload
validation. Existing HTTP stream forwarding is unchanged; clear/revoke affects
the next admission and already-admitted work may finish. Public descriptor text
must contain public examples; validation cannot recognize every secret string.

Original accepted-source checks used Rust 1.94.0 on macOS arm64 with isolated state. Earlier local
release preparation at `af1b45e` encountered the default optimized macOS 27.0.1
`sqlx_macros` loader failure (mis-aligned LINKEDIT string pool); a separate
command-local build-override `strip="none"` retry succeeded. That historical
workaround is not an unmodified native or four-platform build claim for this
project. Actions, optimized artifacts and live providers are separate evidence.

Local acceptance, integration, tagging and publication are distinct. Completing
these checks does not publish a release or authorize changing an installed service.
