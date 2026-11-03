# Changelog

## Unreleased

### Internal

- Box finished internal OAuth bootstrap error responses for current-stable
  Clippy; handlers return the same responses and retain conditional cleanup.

- Give the migration expiry test a ten-second preview setup margin and wait
  from its recorded expiry before apply, retaining the post-expiry conflict
  and unchanged-binding assertions.

- Box the internal HTTP admission error response for current-stable Clippy;
  the handler returns the original response with unchanged admission behavior.

- Use a guarded match for inherited OAuth default-session selection to satisfy
  current-stable Clippy. Existing explicit labels and non-OAuth sources retain
  their behavior.


### Native MCP prerequisite safety

- Add a bounded rmcp3.7.0 HTTP adapter (AGENT-198): whole JSON/error-body and
  cumulative SSE response bounds precede collector/JSON decoding; event,
  depth/work, timeout and cleanup checks apply with explicit unsupported modes.
  Compression, redirects and automatic replay/resumption are disabled. See
  [configuration, diagnostics and limits](docs/development/mcp-transport.md).
  Actual SDK/TLS receiving-process checks distinguish rejected replies from
  already-arrived tool effects. One GET attempt per transport prevents SDK
  renewal from resetting limits; conflicting transfer framing is refused and
  bare CR event delimiters count before parser admission.
  This separate library needs AGENT-202 daemon
  integration and independent acceptance; it does not ship native MCP, clear
  all G1 requirements, bump the root version or change installed services.

### OAuth lifecycle safety

- Reject stale OAuth success, degradation and bootstrap cleanup after revoke,
  recreation or a newer token write. Tokens become usable only after
  the intended sealed row commits. Migration 0010 preserves existing custody,
  grants and selections and prevents older binaries from opening upgraded state.
  Follow [recovery/backup/rollback guidance](docs/user/operator/oauth-recovery.md).
  Already-admitted work may finish; this does not establish crash-safe rotating
  refresh, provider proof or release readiness. No version bump.
### Connector onboarding

- Tool/model operator writes and newly applied seed catalogs now require an
  absolute HTTP(S) base URL without userinfo, query or fragment.
  Localhost/private endpoints, IP literals and normal base paths stay supported;
  non-HTTP infra is unchanged. Correct invalid URLs before their next update or
  newer seed apply; this adds no migration or automatic rewrite. Rejected writes
  preserve existing rows, grants and selections; invalid seed destinations
  leave every row and the seed version unchanged.
- [Connector onboarding change notes](docs/user/changes/connector-onboarding.md)
  collect the operator-to-agent outcome, compatibility/upgrade steps and local
  verification limits. The saved actual-process smoke and independent
  discovery-driven consumer evidence remain separate acceptance layers.
- Personalized `/skill` identifies authenticated guidance without asking the
  caller to refetch and no longer invents a chat operation for the first listed
  service. It retains the existing catalog-backed `/tools` agreement,
  isolation and explicit account/source diagnosis. Use typed JSON discovery for
  service operations; listing and activation do not prove credential readiness.
  Rendered diagnosis includes proxy audit events for selected-source 503s.
  No policy, API, migration or version change.
- Optional versioned HTTP service descriptions let agents construct requests
  from authenticated JSON discovery using their own Locksmith token.
  Operators author nested metadata with `--metadata-file`; only the validated
  public descriptor is projected. JSON/plain-text response examples describe
  reference/customer services without new execution or grant authority. Legacy
  metadata remains compatible; metadata-only changes preserve grants/selections
  while still requiring runtime activation. No migration or version bump.
- A focused [operator onboarding recipe](docs/user/operator/connector-onboarding.md)
  reuses reference/customer setup, inspection, named-agent grants and account
  selection, with receiving-account checks and truthful readiness/repair guidance
 . Unsupported modes and narrower authority claims remain rejected.

### Added

- Finite reviewed HTTP grants pair named agents with explicitly selected accounts,
  with runnable reference and independent customer-service setup instructions.
- Operator reads distinguish active, pending and disabled connections. Saved
  writes that fail activation report that failure while affected routes deny
  admission and unrelated healthy routes remain available.

### Breaking changes

- Credentialed requests require an explicitly selected account for each allowed
  agent. Missing bindings deny access; unavailable selected credentials fail
  closed. Locksmith no longer falls back to a registration default, another
  OAuth session, or an unauthenticated upstream.
- Credentialed legacy routes require a registered agent identity. Clearing a
  binding removes access instead of restoring a default account. Direct
  file-backed bindings require an explicit sealed-snapshot import.

- New agents and bootstrap policies have no implicit HTTP grants. Existing
  policies require finite review, including authless connections; adding a
  registration never expands authority. Unsupported narrower selectors are refused.
- Deleting/recreating a route or changing its upstream/egress clears its grants
  and selections. Deliberate destination review and reapproval are required.

### Upgrade and verification

- Back up a consistent database, preview and review the reference-only mapping,
  apply the selected bindings, then verify the cutover and restart. Existing
  explicit selections are preserved; ambiguous mappings need operator input.
  Follow [the migration guide](docs/user/concepts/migrating-account-bindings.md).
- [The repeatable daemon/CLI smoke](docs/development/explicit-account-bindings-smoke.md)
  covers account attribution, zero-dispatch denials, migration and the documented
  setup commands using synthetic accounts. It does not establish live provider
  compatibility, installed-deployment acceptance, a version tag or publication.
- The binding-repair change guide distinguishes accepted D1 work from remote
  integration and release status.

- For the HTTP grant cutover, stop writers and take a compatible binary/schema/
  configuration/state backup. Use the reviewed `preview --grants` workflow to
  commit finite policy and account references atomically. Old unreviewed bootstrap
  tokens need re-minting; stale plans must not resurrect removed authority.
- See [HTTP grant and activation changes](docs/user/changes/explicit-http-grants.md)
  for saved-but-failed activation repair, next-admission boundaries and limits.
  Original local synthetic acceptance is historical; this projected candidate
  still needs its own receiving checks, remote review and CI. No version/tag or
  live-provider compatibility is claimed.
