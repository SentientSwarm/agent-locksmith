# Changelog

## Unreleased

### Fixed

- Revoking an agent now removes its account bindings, stashed backend
  bindings, grants and native grant sets in the same write, and audits
  their counts (#157). Before, they stayed behind and could not be
  listed or removed once the agent was revoked. `locksmith agent
  prune-revoked [--dry-run]` (`POST /admin/operator/revoked-agents/prune`)
  removes what earlier revokes left: it names agents and routes, never
  credential values, and audits counts only.

### Added

- Broker routes (`--broker` on `tool|model put` and `route backend put`).
  A broker destination picks the provider account itself: Locksmith sends
  one route-level key (sealed with `tool|model set-key` or `route backend
  set-credential`, both reading stdin, or an `op://` reference) and the
  caller's public id in `X-Locksmith-Agent`, replacing any copy the agent
  sends. A broker `put` without `--auth` keeps the route's
  key. Agents select it with `agent set-credential --broker`. An optional
  attribution header is copied into audit as `details.broker_account`
  (hashed when sensitive). An optional health probe refuses a down broker
  with 503 `backend_unavailable` without dispatch, logs transitions, shows
  the last probe as `health` on `tool|model get`, and adds broker counts to
  `/readyz` without failing readiness. `invalid_broker` (400) and
  `broker_kind_change` (409) refuse bad specs and in-place kind changes.
  Migration 0026.
- Route backends (`locksmith route backend put|list|get|delete`,
  `locksmith route switch`). A tool or model route can declare several
  destinations and switch its active one without re-granting agents:
  grants stay on the route and bindings move with the backend. Switches
  need the route revision (`If-Match`), which backend edits also move.
  They are audited as `route_backend_switched` with the destination
  before and after; backend edits as `route_backend_put` and
  `route_backend_deleted`. OAuth backends, native connections and pinned
  routes are refused. Migration 0025.
- Route request profiles (`--profile generic|openai-codex-responses`).
  Codex wire behaviours follow the profile; routes without one keep
  today's inference from the upstream. A profile change keeps grants and
  bindings, because it does not change the destination.
- Per-route upstream CA (#135). `model|tool put --upstream-ca-file` (admin
  field `upstream_ca_pem`) gives one HTTPS route its own trust anchors. The
  route trusts only those certificates: public roots and the global
  `tls.upstream_ca_bundle` are not used for it, and other routes never trust
  them. Any certificate can be the anchor, so a private intermediate alone
  works. Unusable bundles, plain-HTTP upstreams and native MCP routes are
  refused with 400 `invalid_upstream_ca`. Changing or removing a route's CA
  clears its grants and account bindings, as an upstream change does.
  Migration 0023 adds the column; a 3.0.0 binary cannot open a database
  after it, so roll back by restoring a backup.
- `locksmith oauth device-login <name> [--label] [--replace]` and its admin
  API sign a ChatGPT-plan (codex) session in, or reconnect a degraded one,
  through OpenAI's device authorization. The daemon runs the code exchange,
  so no token reaches the operator's shell. A session needing reconnection is
  replaced in place and agent bindings to its label keep working (#138).

### Fixed

- Route backends (#155): the active-backend check on `route backend put`
  and `delete` now runs inside the write, so a concurrent switch cannot
  let an edit land on the live destination. `route backend list` and
  `get` show the active backend from the route itself. A non-numeric
  `If-Match` on `route switch` is 400 `if_match_invalid`, not 409
  `revision_conflict`.
- Point upstream URLs in `Link` and `Location` response headers back at
  Locksmith. GitHub pagination returned `Link: <https://api.github.com/...>`,
  so following `rel="next"` bypassed Locksmith and failed without a
  credential. Link targets under a route's upstream base now become
  `<scheme>://<Host>/api/<route>/...`. Other URLs, URLs embedded in another
  URL's query and links to the bare upstream base are left unchanged.
- Forward every value of a repeated response header. Only the last
  `Set-Cookie` or `Link` value reached the agent before.

## 3.0.0

- Bind the bootstrap-only enrolment listener when `listen.bootstrap_only` is
  enabled. Previously the setting was parsed but nothing bound it, so mtls-only
  deployments had no enrolment path. It needs `listen.admin_socket`; startup
  fails when that is missing, when `host` is not an IP address, or when the
  port or certificate cannot be used.
- Verify the bootstrap secret before agent registration creates the agent.
  Previously a caller holding only a token's public id could create and then
  revoke an agent under any name, permanently reserving that name.
- Own native preparation request bodies before buffering through daemon shutdown,
  retaining independent body and operation budgets.
- Fail daemon startup immediately when the admin socket or admin HTTPS port
  cannot be bound, and stop the daemon with an error-level log when any listener
  stops before shutdown. Previously the daemon kept serving agents without its
  admin surface and reported the error only when stopped. Listener "bound" log
  lines now show the actually bound address, so a configured port 0 is usable.

### Changed

- Publish the daemon. Earlier releases shipped only the `locksmith` CLI for
  each platform; there was no `locksmithd` download. A release now carries
  `locksmith-SUFFIX` and `locksmithd-SUFFIX` for Linux amd64/arm64 and macOS
  amd64/arm64, built natively with Rust 1.94.0 and `--locked`, smoke-tested on
  their own platform, plus `SHA256SUMS` and `validation.json`. The CLI asset
  names are unchanged. Release notes come from this changelog, and a tag is
  published only when its commit has a successful CI run on `main` or
  `release/**`.
- Document that config changes need a restart. Earlier docs said the YAML
  config could be hot-reloaded; nothing reloads it, and there is no `SIGHUP`
  handler or `config reload` command. The architecture guide now lists what
  changes live through the admin API (registrations, agents, grants,
  bindings, credentials, OAuth, definitions) and what needs a restart (the
  config file, operator credentials, certificate paths).
- Correct docs and CLI help that described behaviour the product does not
  have: audit event classes and `--until-ms`, `--body-limit` (request
  bodies only) and the egress default, proxy error codes and the stream
  truncation marker, mTLS handshake refusals, and several commands and
  flags that do not exist.
- Give every admin error a `type`. Admin socket, admin HTTPS and
  bootstrap-listener errors carried only `code` and `message`; `type` is
  now filled from the HTTP status (for example `auth_error` for 401,
  `not_found` for 404) when a handler did not set one. Existing `code`
  values are unchanged.
- Add `code` to proxy errors that lacked one: 400 `bad_request`, 502
  `upstream_error`, 502 `response_content_type_disallowed`, 502
  `response_size_exceeded` and 504 `timeout`. Their `type` values are
  unchanged.
- Log deprecated config fields. Logging now starts before the config is
  read, so the one-time warning for each deprecated field reaches the log;
  it was previously dropped.
- Honour `logging.file`. The setting was accepted but ignored; log lines
  now go to that file (appended, created with mode 0640) instead of
  stdout, and startup fails if it cannot be opened.
- Make the shutdown drain window a hard bound. Requests still in flight
  when it ends are dropped and the listeners close; previously each
  listener could take up to six more seconds.
- Record the refused certificate's serial in `details.serial_hex` of
  `revoked_by_crl` and `revoked_by_blocklist` audit rows; it was null.
- Enforce mTLS revocation on the agent listener. `listen.mtls.blocklist_path`
  and `listen.mtls.crl_url` were accepted but never reached the validator, so
  a serial added with `locksmith mtls revoke` or listed in the CA's CRL still
  authenticated. The daemon now loads both, fetches the CRL before serving and
  every `crl_refresh_interval_seconds`, and re-reads a changed blocklist every
  `blocklist_reload_interval_seconds`; refusals audit `revoked_by_blocklist`
  or `revoked_by_crl`. A CRL (PEM or DER, at most 8 MiB) is applied only when
  it is complete, a CA certificate in the agent CA bundle that matches its
  issuer and may sign CRLs signed it, it has a CRL number and an unexpired
  `nextUpdate`, and neither its CRL number nor its `thisUpdate` goes backwards
  for that issuer. CRL state is kept per issuer name and signing key, and
  certs are checked against the CRL of the CA whose key signed them, so one
  CA's CRL never removes or masks another's revocations, even when two CAs
  share a name during a rotation. Each issuer's distribution point is pinned
  once seen, so a CRL for another partition of the same CA is refused. The
  last good CRL is kept in `mtls-crl-cache.pem` beside the database and
  reloaded per issuer at startup, even past `nextUpdate`, so a restart while
  the CA is unreachable keeps known revocations. A failed fetch keeps the
  previous snapshot and retries within 30 seconds. While no CRL has ever been
  applied (first start with the CA down and no cache), every mTLS client is
  refused and audited as `crl_unavailable`. The fetch trusts the agent
  CA bundle and `tls.upstream_ca_bundle` as well as public roots. Blocklist
  serials are canonicalised (`7A:11`, `0x7a11` and `007a11` match `7a11`),
  non-hex lines are skipped with a warning, and `locksmith mtls revoke`
  rejects a non-hex serial and replaces the file atomically.

- Attribute a strictly shaped `bad_code_verifier` token refusal to a closed
  `token_verifier_refused` reason, and add a stdlib helper that transforms only the
  authorization challenge in a private connect receipt. Acceptance predicates and
  explicit account and grant authority are unchanged. See
  [refusal and lifecycle boundaries](docs/user/operator/oauth-capability-proof.md).

- Add a [nonpublishing native candidate lane](docs/development/native-validation.md)
  with bounded build, smoke and artifact checks for four targets; local fixtures
  do not establish platform execution or release publication.

- Decode documented Slack workspace display labels in declared identity checks
  while retaining exact observed IDs, bot refusal and token echo validation;
  expose [closed identity diagnostics](docs/user/operator/slack-identity-diagnostics.md).

- Add [declared custom OAuth contracts](docs/user/operator/custom-oauth.md) for exact scopes, independently verified user/workspace or service-principal identities, none/confidential clients and explicit Slack response variants. Existing named contracts remain unchanged. Migration 0022 preserves custody and sequence highwaters; old binaries refuse the new schema.

- Report [closed Slack token metadata reasons](docs/user/operator/slack-token-diagnostics.md)
  through the existing attempt/refresh status path. Missing, null, wrong-type and
  conflicting metadata remain refused without provider values or token hashes.
  Acceptance, identity/scope checks and custody are unchanged; reason enums are
  additive, with no migration. Historical broad failures remain undiagnosed.

- Permit an absent Slack response issuer only at the dedicated, issuer-distinct
  `/oauth/callback/slack` redirect, with actual Host/path checked against sealed
  attempt state before claim. Supplied issuer checks and legacy/Linear mandatory
  issuer behavior remain. [Callback upgrade](docs/user/operator/slack-callback.md)
  requires a new client generation and explicit reactivation; no migration or
  automatic custody rebind. Offline TLS controls do not establish live acceptance.

- Separate the fixed Slack OAuth resource `https://mcp.slack.com` from MCP
  transport `https://mcp.slack.com/mcp` across activation, custody checks and
  native sessions. The old real-kind `/mcp` resource now refuses explicitly;
  [deliberate binding repair](docs/user/operator/slack-oauth.md#renewal-retirement-and-upgrade)
  is required. Existing Linear and local fixture behavior remains. Offline
  receiving evidence does not establish live Slack confidential-S256 acceptance.

- Add an explicit [confidential Slack user profile](docs/user/operator/slack-oauth.md)
  through owner-bound sealed client/token custody and customer definition activation.
  S256/client authentication, exact identities/scopes, finite tool authority and
  deliberate refresh repair are exercised against an invented TLS receiver.
  Migration 0021 preserves custody/highwater and permanently retires client generations.
  Preserve closed deadline/HTTP diagnostics; no live provider acceptance is claimed.

- Add explicit [finite-v2 native contracts](docs/user/operator/native-contract-policy.md)
  for supported customer None/bearer/OAuth sources through existing review/grants.
  Customer registrations can explicitly select names after the same complete
  bounded catalog scan, with declared omissions and no early publication.
  Preserve bounded inert metadata, scalar default annotations and up to 64 input
  enum values. Open-empty input requires a digest-bound empty-arguments restriction
  with a separately labeled callable schema. V1 bytes/output rules remain; old
  readers refuse the new marker. Migration 0020 permits dedicated definition policy
  activation/reset while preserving immutable pins and active configuration; prior
  schema-19 daemons refuse the newer database. No provider acceptance or timeout change.

- Add a fixed [hosted Linear OAuth profile](docs/user/operator/hosted-linear.md)
  and an explicit local fixture kind through existing owner custody, refresh,
  native selection and finite grants. Hosted observation scans a bounded complete
  catalog and retains only explicitly selected original contracts with omission
  counts; unsupported selected schemas refuse. Public callback authority is
  separate from the loopback TLS bind. Migration 0019 preserves custody/highwater
  and refuses prior daemons. Live shipping provider adoption remains separate.

- Connect the [local customer MCP journey](docs/user/operator/customer-mcp-journey.md)
  from definition promotion through account selection, finite review/grants,
  ordinary task discovery and deliberate repair. Clarify that controlled refresh
  invalidates existing native authority without creating grants. Live-provider
  acceptance remains open.

- Add deliberate CAS-controlled activation/deactivation for immutable `local.*`
  customer definitions: explicit None, live StoredBearer or configured controlled
  OAuth. Import/creation/promotion create no account or grant. Full authority
  repair follows real transitions; current exact-state retries only resync.
  Migration 0018 refuses older whole-daemon startup. Builtin providers and full
  readiness remain open. See [setup and recovery](docs/user/operator/integration-definitions.md).

- Add deliberate owner-bound [controlled OAuth native selection](docs/user/operator/native-oauth.md),
  finite preparation and standard/compact dispatch through the existing admission path.
  Refresh/version or trust changes require renewed preparation and a fresh session;
  reconnect requires reselection. Access-only materialization preserves optional refresh.
  Migration 0017 refuses older whole-daemon startup; hosted providers remain unproved.

- Add manual owner-bound controlled refresh and explicit fresh-consent repair.
  Migration 0016 commits pending uncertainty before I/O and exact current custody
  before success, preserving optional expiry/scope and claimed refresh retention.
  Status/revisions and the [JSON contract](docs/user/operator/oauth-account-response-v1.schema.json)
  expose pending/reconnect state. Legacy kind barriers remain; no automatic refresh,
  hosted provider acceptance or agent/native authority. Prior schema-15 binaries
  refuse upgraded state; restore only a full prior snapshot under recovery rules.

- Add [controlled operator consent](docs/user/operator/oauth-consent.md) with
  public-ID ownership, sealed `connected_unbound` custody, strict twin identity
  checks and revision-checked disconnect. Migration 0015 preserves legacy custody;
  older binaries refuse the new schema/config. Hosted provider acceptance and
  native OAuth activation remain outside this increment.

- Document and exercise [sealed-state recovery](docs/user/operator/sealed-state-recovery.md):
  SQLite-consistent snapshots, separate stored/OAuth key custody, isolated restore
  and selected-account verification. Missing/wrong keys, revoked-owner quarantine
  and uncertain refresh remain fail-closed; no new keychain or key-rewrap command.

- Align contributor builds and CI on tested Rust 1.94.0. The
  [build recipe](docs/development/build-identity.md#build-with-the-tested-recipe)
  is one command on every host, preserving runtime optimization and native
  output paths. It distinguishes locally validated macOS ARM64 artifacts from
  remaining platform work; the release workflow is unchanged, and this is not an
  MSRV or full release-readiness claim.

- Add configuration-free `--build-info` JSON to both binaries and shared build
  metadata to `/version`, preserving short version output and release names.
  `locksmithd --version` now prints the same short form as `locksmith --version`.
  The [captured-file verifier](docs/development/build-identity.md) checks an
  independently expected commit, clean source state, binary roles and checksums.
  These local consistency checks do not establish release or platform readiness.

- Add an explicit per-connection compact MCP facade with pinned local search,
  complete describe receipts and the existing committed native dispatcher.
  Standard/compact share session and request limits; fixed context and account
  authority are unchanged. Opt-in invalidates existing connection/tool authority;
  older strict-parsing daemons cannot start with opted-in rows. This bounded local
  increment does not establish provider compatibility or model-efficiency gates.

- Preserve HTTP/native discovery protocol and public paths in authenticated
  `/skill`, with complete-schema native request guidance, fixed-context/pin and
  current-grant limits, safely rendered display data and protocol-specific repair.
  Native connections do not inherit HTTP Codex recipes by name. See the
  [skill reference](docs/user/agent-integration/skill-reference.md). Guidance reads
  do not materialize credentials or contact upstreams; auth/cache behavior and
  existing wire/authority contracts are unchanged. This is bounded AGENT-209 work,
  not full onboarding or live-provider acceptance.

### Internal

- Add the `qa/` black-box qualification harness: a surface contract checked
  against every route and CLI command, PASS/FAIL/NOT_EXERCISED/NOT_APPLICABLE
  statuses with per-area floors, redaction-scanned evidence bundles, and
  about 300 smoke cases covering every route, CLI command and daemon
  behaviour, run against the release binaries in CI. See `qa/README.md`.
- Admin HTTPS in mTLS mode now logs `admin HTTPS listener (mTLS) bound` once,
  after its TLS configuration loads. It previously logged both
  `admin HTTPS (mTLS) listener bound` and, from the shared serve loop,
  `agent listener (mTLS) bound` with the admin address. The agent listener's
  messages are unchanged.

- Start daemon integration tests on port 0 and read the bound address back
  instead of probing a free port and releasing it, which another process could
  take first under parallel load. The admin HTTPS off-by-default tests now hold
  the configured port, so a daemon that tried to bind it would fail startup.
  The explicit-binding smoke keeps a stable port because its upgrade probes run
  prior binaries.

- Keep symbols in build-time artifacts of release builds
  (`[profile.release.build-override] strip = false`). The macOS 27 `strip`
  corrupts proc-macro dylibs, which broke `cargo build --release`; shipped
  binaries keep the default release stripping.

- Make native ingress/body deadline tests use explicit pending/body barriers and
  controlled Tokio time, with a nondefault five-second request budget for real
  authenticated recovery on the same runtime. Production deadlines and authority are unchanged.

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


### Fixed native context and diagnosis

- Review typed nonsecret fixed top-level values, deliberately grant the exact
  contract, and expose a truthful callable schema that omits protected fields.
  Reject any caller override, inject once, validate merged limits and screen the
  current selected secret before persistence or upstream I/O. Empty context keeps
  existing bytes/digests. See [operator guidance](docs/user/operator/native-context.md).
- Refuse a combined schema/context contract that exceeds the grant reader's
  JSON budget before saving it; keep existing reviews and grants unchanged.
- Add safe phase/reason/correlation diagnostics, current-state repair hints and
  observable mirror failure. Missing outcomes remain unknown; checked results
  survive later cleanup/diagnostic failure when locally available. Async waits
  are bounded; synchronous filesystem calls are not a hard50ms guarantee.
- Keep schema14. Accepted pre-context B refuses whole context-bearing mixed
  inventories; re-upgrade preserves reviews/revocation and needs fresh observation.
  Bounded207 local acceptance and full207/208/provider acceptance remain
  separate; [checks and limits](docs/development/native-protected-context.md).

### Native reviewed dispatch

- Enable manual native None/live sealed-bearer tools through current account,
  observation, reviewed contract and finite grant intersection. A first list
  pins exact contracts within its original session scope; empty pins cannot
  expand. Every call validates arguments
  and commits a safe admission record before one upstream submission.
- Bound supported text/structured results, enforce known-token screening and
  preserve uncertain outcomes without retry. Re-observe after60s or restart.
  Stage B adds no migration; schema14 downgrade retains state but loses positive
  dispatch. See [agent workflow](docs/user/agent-integration/native-mcp.md) and
  [implementation/verification](docs/development/native-dispatch.md). Full206 and
  provider/compact acceptance remain open; bounded fixed context is above.

### Native tool preparation

- Add operator-only observe/inspect/review/finite grant replacement for manual
  native None and sealed-bearer accounts, with matching strict CLI/API. Stage A
  initially retained empty lists and denial; stage B above adds reviewed calls. See the
  [workflow, limits and upgrade](docs/user/operator/native-tool-review.md).
- Use the bounded outbound adapter with duplicate-safe raw response checks,
  approved-address pinning, verified TLS, finite complete observations and
  generation/source CAS. Migration0014 starts with zero preparation and refuses
  schema13 binaries. Drift, binding/config/name lifecycle and restart freshness
  cannot silently restore prepared authority.
- Stored bearer stdin ingestion explicitly replaces header shape and commits
  sealed storage plus selection together; deliberate sharing requires a live
  reference. This is AGENT-206A only, without full206 or provider
  acceptance. Useful dispatch is described in stage B above.

### OAuth refresh recovery

- Commit refresh uncertainty before token I/O and publish a rotated pair only
  after custody commits. Interrupted accounts remain unavailable across restart,
  even with unexpired old access; status/list expose reconnect-required state.
  Local revoke plus freshly issued credentials is the explicit recovery path.
- Migration0013 preserves existing custody/authority and makes schema12 binaries
  refuse upgraded state. Current bootstrap/inline/background OAuth scopes stop
  before daemon return releases database ownership. See [recovery and upgrade](docs/user/operator/oauth-recovery.md).
  This is bounded local AGENT-205 only; consent204, provider policy/live T14
  and full205 acceptance remain open.

### Integration definition authoring

- Add strict immutable definition import/get and create-only disabled native
  instances through matching operator CLI/API. Pins include exact revision,
  content digest and descriptive auth profile; no provider request, credential,
  account selection or authority is created. Candidate reference/customer
  examples use the same validation. See [operator workflow](docs/user/operator/integration-definitions.md).
- Migration0012 preserves existing state and makes older binaries refuse the
  upgraded database. Derived rows reject general edits/enable; credential
  attachment and sealed storage now commit together, including rollback on
  pinned replacement. See [upgrade and limits](docs/user/changes/integration-definitions.md).
  This is independent AGENT-203 authoring only: full203 and live195/196/200,
  setup194 and G0/G1 remain pending.

### Native MCP lifecycle

- Add authenticated stateful MCP2025-11-25 lifecycle at `/mcp/{connection}`
  (AGENT-202), with native-scoped Host/Origin/input/output limits, current
  connection authority, bounded joined sessions, replay refusal and shutdown.
  Tools remain unapproved: empty list and explicit call denial, no upstream
  credentials or calls. Typed native connections cannot use HTTP `/api`.
- Migration0011 preserves HTTP accounts/grants/revocations and reviewed receipts,
  creates zero native/tool authority and makes old binaries refuse upgraded state.
  Protocol/config changes require connection-grant/account reapproval; one daemon
  owns each database. See [setup](docs/user/operator/native-mcp.md),
  [wire contract](docs/user/agent-integration/native-mcp.md) and
  [backup, recovery and limits](docs/user/changes/native-mcp.md).

### Native MCP prerequisite safety

- Reserve MCP session capacity before SDK allocation (AGENT-199). Scoped
  budgets include initializing and closing sessions; worker/service joins and
  response cleanup precede release. A pinned SDK ownership patch retains
  protocol handling and makes stalled-handshake and canceled-close cleanup
  observable. Absolute lifetime also bounds initialization; dropping its unpolled
  response retires the session without invalidating consumed final events.
  See [scope, budgets and limits](docs/development/mcp-sessions.md).
  Resume/replay are unsupported; already-submitted effects are not rolled back.
  The prerequisite was accepted at e18da87; AGENT-202 now consumes its pool.
  Full G3 acceptance remains open.

- Add a bounded rmcp3.7.0 HTTP adapter (AGENT-198): whole JSON/error-body and
  cumulative SSE response bounds precede collector/JSON decoding; event,
  depth/work, timeout and cleanup checks apply with explicit unsupported modes.
  Compression, redirects and automatic replay/resumption are disabled. See
  [configuration, diagnostics and limits](docs/development/mcp-transport.md).
  Actual SDK/TLS receiving-process checks distinguish rejected replies from
  already-arrived tool effects. One GET attempt per transport prevents SDK
  renewal from resetting limits; conflicting transfer framing is refused and
  bare CR event delimiters count before parser admission.
  The library was accepted at f0c4ca8. N1 consumes its session layer but has
  no reachable outbound operation; later observation/dispatch must use this
  adapter and prove its actual daemon effects. Full G1 stays open.

### OAuth lifecycle safety

- Reject stale OAuth success, degradation and bootstrap cleanup after revoke,
  recreation or a newer token write. Tokens become usable only after
  the intended sealed row commits. Migration 0010 preserves existing custody,
  grants and selections and prevents older binaries from opening upgraded state.
  Follow [recovery/backup/rollback guidance](docs/user/operator/oauth-recovery.md).
  Already-admitted work may finish; this does not establish crash-safe rotating
  refresh or provider proof.
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
  Original local synthetic acceptance is historical. Live-provider
  compatibility is not claimed.
