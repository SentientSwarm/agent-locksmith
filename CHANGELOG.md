# Changelog

## Unreleased

### Removed

- **Breaking:** legacy mode (AGENT-297). The daemon refuses to start
  without `listen.admin_socket`, so every request comes from an enrolled
  agent. Legacy mode served authless `tools` entries behind an optional
  shared `inbound_auth` token, and when that was missing or misconfigured
  anything that could reach the listener could use them. Set
  `listen.admin_socket`, `database.path` and `operator_credentials_path`,
  then enroll agents; `tools` entries are imported as registrations.
  `config.example.yaml` now sets all three.
  The refusal comes before the daemon creates the database directory or
  its lock file (AGENT-318).
  The identityless code paths behind it are gone too (AGENT-318): the
  shared `inbound_auth` bearer authenticates nobody, `/readyz` no longer
  reports `agent_identity_required`, and the 401 `agent_identity_required`
  error code is retired. `inbound_auth` is still accepted and ignored, with
  a warning when a token is set.

### Fixed

- A device login whose provider answers a redirect now says Locksmith
  does not follow provider redirects and that the route's `token_url`
  and `device_url` must be the provider's final URLs, instead of a bare
  status (AGENT-328).
- Under `fail_open`, a streamed output written to again after it
  finished counts against the lane limit, so an upstream can no longer
  hold a window per output for up to 1024 outputs; the bound is about
  64 windows of `max_scan_bytes` (an eighth more under `flag` or
  `pass`), bridges included (AGENT-273).
  Azure "On Your Data" text (`choices[].messages[].delta`) is scanned
  across chunks, so a key split between chunks is caught.
- A token endpoint that answers a redirect now fails the refresh with
  cause `token_redirect` and a message naming `token_url`, not as
  `provider_5xx` (AGENT-302). Token calls still do not follow redirects.
- The upstream base-path check refuses a path holding a NUL (`%00`),
  decoded or still escaped at the decode bound, since an upstream reading
  it as a C string sees `..%00` as `..`. That includes a literal `%2500`
  in data (`50%2500off`), which a double-decoding upstream reads as a NUL. A decoded `?` or `#` ends the
  path to an upstream that re-parses it, so the path cut there must stay
  inside the base too (`..%3F`). A further reading drops Unicode's
  default-ignorable characters (zero-width, bidi controls, variation
  selectors, tag characters), held alongside the others, so `.` + U+200B
  + `.` can't climb out on an upstream that ignores them (AGENT-287).
- Under `fail_open`, a key split between two joined outputs (Anthropic
  text blocks, Responses content parts) no longer reaches the agent whole
  when an out-of-order output starts between them (AGENT-328). That
  output joins before the others, so it now takes no tail and leaves the
  group's latest output, open or finished, to lend its tail to the next;
  the split is caught and the stream blocked.
- Under `on_hit: redact` with `fail_open`, a streamed key whose start went
  out before the key was complete (held events released early past
  `max_scan_bytes`) is no longer audited as redacted while that start
  reaches the agent (AGENT-330). Only the rest of it was cut; with long
  event fields, 15 to 27 characters of a token could go. The stream is now
  blocked with `redaction_incomplete: true`, as the documented contract
  says for a redaction that can't remove every match. The same holds for a
  match (a PEM key) that grows over text already released.
- Request inspection also reads a path whose decoding contains a `?`
  (a double-encoded `%253F`) with the text after it as a form query, `+`
  as a space (AGENT-315). An upstream hop that decodes the path again and
  re-parses it sees a query there, so `ignore+all+previous+instructions`
  hidden that way is now judged as the words it becomes.
- Under `on_hit: flag` (or `pass`), a stream window that has passed
  `max_scan_bytes` no longer rescans its whole held text on every chunk
  (AGENT-315). Once pinned at the cap, as when padding or a long run of
  blank text keeps it full, each chunk rescanned up to the cap. Such a
  window now runs up to an eighth over the cap until its next scan and
  scans once an eighth of what it holds is new, as below the cap; each
  scan sees all the text a scan of every chunk would have. A stream that
  redacts or blocks keeps scanning every chunk past the cap: under
  `fail_open`, that is what finds a key while its events are still held
  once the held events pass the limit, and batching there let keys out.
- Stream inspection now catches a secret split between two outputs that
  clients join into one text (AGENT-329): an Anthropic message's text
  blocks, or Responses content parts, which the SDK's `output_text` joins.
  Each output had its own window, so the halves were scanned apart and the
  agent could rebuild the key. Each output keeps its own window, and its
  start is also scanned together with the group's kept tail so far, so a
  match crossing the join is found. Its start has already gone out with the
  earlier output, so under `on_hit: redact` the stream is blocked before the
  rest goes, with `redaction_incomplete` in the audit row, rather than
  claiming a redaction; under `block` it blocks and under `flag` it is
  flagged. Only those two kinds of output join, in index order, and carried
  tails count toward `max_scan_bytes`. Under `fail_closed`, text sent to an
  output after a later one of its group has started blocks the stream
  (`joined stream outputs interleaved`), as does an output starting below an
  earlier one (`joined stream outputs out of order`).
- An OAuth bootstrap or device login no longer stores a session for a
  registration its serving catalog shows as infra (AGENT-302). Both
  refuse infra registrations up front from the database, but a catalog
  that still showed the name as infra (after a failed catalog refresh,
  or a change during the call) let the exchange go on. Both now answer
  409 `authority_changed` ("start again") and store no new session.

- A large MCP task list (`tasks/list`), or an MCP server's own request
  (`sampling/createMessage`, `elicitation/create`), streamed over SSE is
  no longer blocked under `fail_closed` past 255 strings (AGENT-323).
  Like the MCP results below, each is complete in its event and is
  scanned whole: a task list under its `tasks`, a request in its
  `params`. MCP notifications, such as progress and log messages, keep
  their windows.

- A large MCP result streamed over SSE (a `tools/list`, `resources/list`
  or `prompts/list` result, a read or a tool call's output) is no longer
  blocked under `fail_closed` with held events (AGENT-273). Each of its
  strings took a window of its own, so past 255 the stream was refused.
  An MCP result is complete in its event, so the strings under its
  member are now scanned whole; its other fields and other JSON-RPC (A2A
  or ACP chunks, which clients join) keep their windows. A
  JSON-RPC stream that later sends JSON that is not JSON-RPC now blocks
  under `fail_closed` ("stream event names another protocol"); under
  `fail_open` it keeps its windows and is audited as a hold overflow.

- A key split across a streamed Gemini candidate's text parts, within one
  chunk or from one chunk's later part to the next chunk's first, is now
  redacted (AGENT-321). Each part had its own window, while clients join
  every text part of a candidate in order; the parts, thoughts included, now
  share one, named by the candidate's position, since clients ignore its
  `index`, whatever `choices`, `type` or event name the chunk also carries
  (AGENT-322). Under `fail_closed` with held events, a thought part after
  its candidate's answer text is blocked (a client leaving thoughts out
  would join the answer around it), as is a chunk clients read in different
  ways: a `candidates` (other than `null`) or `parts` that is not an array,
  a candidate whose `index` is not its position or that has none past
  position 0, or a `thought` that is not a boolean.

- A streamed Gemini reply under `redact` or `block` is no longer held
  longer than its text needs (AGENT-273). Its `modelVersion`,
  `responseId`, `usageMetadata`, each candidate's `role` and
  `finishReason`, and a part's `thoughtSignature` come whole, so they are
  scanned in their event instead of in a window. A short field repeated
  in every chunk (`role`, a usage `modality`) kept every event held until
  its own window passed the match overlap, two to three times as long as
  the text alone, and under `fail_closed` a long reply could be blocked
  for holding past `max_scan_bytes`; a thought signature held the stream
  to its end.

- Under `fail_closed`, a streamed chat reply with many or long tool calls
  is no longer blocked once the whole tool-call section, as raw SSE,
  passes `max_scan_bytes` (AGENT-273). A tool call is now finished, judged
  and released when a later-numbered call in its choice starts, so only
  the call in progress must fit. An upstream that interleaves tool calls
  is blocked under `fail_closed`; `fail_open` is unchanged.
- Under `fail_closed`, a streamed chat reply that starts a tool call below
  a higher-numbered call of its choice, or with a negative index, is now
  blocked (AGENT-317). That call was inspected in a fresh window, so a key
  split between it and the call before was never seen whole, though a
  client merging calls by position would join them. A choice or tool
  call sent without an `index` among indexed ones is blocked too, as is
  one past the first of its chunk in a stream that sends no index, and
  any output index that is not a plain integer up to 2^53 (`"1.0"`, `1e0`,
  `"1"`), which clients read in different ways. Servers that send parallel
  tool calls in one chunk without an index are blocked too. The index check
  covers an array element's `index` at any depth, such as OpenRouter
  `reasoning_details` (AGENT-319), and skips a top-level `index` that the
  stream's protocol does not use.
- A request can no longer climb out of a route's base path with dot segments
  or separators only some upstreams read as such: split by a tab or newline
  (`.%09.`), or spelled with characters NFKC maps to `.`, `..`, `/` or `\`
  (`%EF%BC%8E`, `‥`, `／`), including one such `.` that a following `..` would
  otherwise pop. The path must stay inside both as a strict upstream and as a
  lenient one reads it. A path holding an overlong UTF-8 or `%uXXXX` escape
  (`%c0%ae`, `%c0%af`, `%u002e`) in any reading is refused outright. A lead
  that can start an overlong form is read with the bytes after it, escaped or
  literal, as a decoder that skips the continuation check would, and refused
  when that is overlong, whatever it spells: `%E0@n` and `%e0%40%6e` (`.`), an
  overlong `．`, and a continuation encoded at another depth or joined by a `%`
  after a decode (`%25e0%80%ae`, `%e0%2580%25ae`). Forms never valid in UTF-8
  (`%F8`-`%FF`, or above U+10FFFF) are also refused when their value is ASCII
  once cut to 21 or 16 bits. Valid UTF-8 always passes, and most Latin-1
  letters do (`s%F8ren`, `voil%E0/x`, `%FC%FD`); a few pairs are refused: `À`
  or `Á` (`%C0`, `%C1`) before anything, `à` before an uppercase letter or
  `_`, and `ð`, `ø`, `ü`, `þ` or `ÿ` before `@` or an early uppercase letter.
  Either way the request gets 400 `upstream_path_escape` (AGENT-287).
- Edge components take `private_network = true` (`PrivateNetwork=yes`),
  set for the offline inspector in the example site, and the start guard
  refuses a secret-holding component while `fs.suid_dumpable` is `1`,
  which would leave its execute-only binary dumpable (AGENT-288). The
  edge guide says to reinstall a model cache found under `$R/inspector`
  into `$R/models/inspector` and delete the old copy, and to set
  `fs.suid_dumpable` on the Incus host, since a container cannot.
- `locksmith rate-limit list` (`GET /admin/operator/rate-limits`) gives
  each limit `enforced`, false when its route is gone, disabled, or no
  longer an HTTP model or tool route. Such a limit is kept, and applies
  again once the route is an enabled one (AGENT-272).
- The `injection` scanner also reads a phrase that combines a glued
  emoji letter (a flag, `ℹ️`, `Ⓜ️`) with a look-alike only the new fold
  reads, such as `ígnore previous instructions🇺🇸` (AGENT-315).
- An OAuth refresh whose token call fails now writes an
  `oauth_refresh_reconnect_required` operational-log warning (AGENT-302).
  The session was already left `reconnect_required`, but only a
  background failure before the token call reached the operational
  log, and a refresh made for a request wrote nothing at all.
- A streamed response on a route whose `fail_closed` policy includes a
  sidecar is refused with 502 `inspection_blocked` before any header is
  sent, instead of 200 headers and an SSE error event, which was framed
  for OpenAI even on an Anthropic stream (AGENT-278).
- A sidecar scanner that reads a large request slowly can no longer hold
  a scan past `timeout_ms` or the scan's deadline: the request is
  written without blocking, and each wait for room is given only the
  time left, so a small send buffer (macOS's is 8 KiB) cannot turn one
  write into many waits (AGENT-278).
- The `injection` scanner folds look-alike letters that have a Unicode
  compatibility form (Kelvin sign, Roman numerals, circled and
  parenthesized letters, superscripts, accented letters, ligatures,
  mathematical Greek), plus small capitals, dotless `i`/`j`, negative
  circled and squared letters and regional indicators, and drops
  combining marks from every script (AGENT-315). A character this
  makes into a letter (an accent, a flag, `ℹ️`) could glue onto a phrase
  and hide it, so text holding one is also matched with the previous
  fold; symbols such as `™` keep their own form. A redaction now covers
  combining marks on the phrase's last letter.
- `GET /admin/operator/egress/policy` reports an unreadable agent-binding
  table as 503 `bindings_unavailable`, not `registrations_unavailable`
  (AGENT-302). The operator guide now names the `oauth_refresh_degraded`
  and `oauth_refresh_skipped` operational-log warnings.
- The edge start guard refuses a secret-holding executable whose
  directories, as written or resolved, someone other than root could
  change, since a writable directory lets the binary be swapped
  (AGENT-288). The path is walked one component at a time, so a
  directory a link leads through is checked too. `install_model.py` runs
  only as root: as another user its
  own directories counted as trusted cache parents. The edge guide now
  says a compromised sidecar can make `op` run and read its output, so
  it has every secret the 1Password service account can read.
- A request can no longer climb back into a route's base path with
  other `;` parameters (`../a;x`, `..;/..;/base;v=2`), which an upstream
  that keeps parameters serves as another resource, nor through a
  segment that is only parameters (`../;x/a`, `.;x/..;/y`): the path
  must stay inside whether the upstream drops parameters or does not
  know them (AGENT-287). A decoded `\` inside a segment
  is also read as a separator, for an upstream that keeps `%2F` as data
  but splits on it.
- A route whose upstream base path holds an encoded separator
  (`/projects/group%2Fproj`) no longer lets a request climb out of it
  and spell the decoded base again (`%2e%2e/%2e%2e/projects/group/proj`),
  which an upstream reading `%2F` as data serves as another resource
  (AGENT-287). Each decoding of the path is now held to the same
  decoding of the base, and so is a reading that splits the path first
  and decodes each segment on its own, as an upstream that keeps `%2F`
  as data but decodes `%252e%252e` to `..` does.
- A PEM private key joined onto its `BEGIN` line with spaces, headers
  and all, with no `END` line within 8 KiB, is redacted to its last
  base64 word, in a body or a streamed response (AGENT-311). Before,
  only the `BEGIN` line was removed and the key was forwarded.
- A streamed response no longer runs out of outputs to inspect at
  about 15 parallel tool calls under `fail_closed` (AGENT-273). Each
  call takes two of the 31 outputs a stream could inspect at once;
  under `fail_closed` the limit is now 255. `fail_open` keeps 31, since
  there each output's window can hold up to `max_scan_bytes`. The
  tool-call section must still fit in `max_scan_bytes` as raw SSE.
- A sidecar's hit `rule` is kept to 64 plain characters before it is
  audited; other characters become `_` and the hit is kept (AGENT-278).
  A streamed response keeps its first inspection error, so under
  `fail_open` a later scan error no longer hides that a sidecar did not
  run.
- `locksmith egress policy --pipelock` quotes a single-label host
  spelled like a YAML 1.1 boolean (`yes`, `no`, `on`, `off`, `y`, `n`),
  which a YAML 1.1 parser would otherwise read as `true` or `false`
  (AGENT-302).
- A request refused because its OAuth token refresh has no egress
  writes the `egress_unenforced` security audit event, as a refused
  proxied request does and as the egress docs say (AGENT-302). It was
  audited as `oauth_unavailable` with cause `egress_unenforced`.
- An agent kept over a limit writes at most one `rate_limited` audit
  row per route a minute for rate refusals and one for concurrency
  refusals, not one per refused request (AGENT-272). Each row's
  `details.suppressed` counts the refusals of its kind since the
  previous one, and a changed limit starts a new minute.
- An OAuth session whose token call has no egress (a proxied route with
  no egress proxy) is reported once, in the daemon log and as an
  `oauth_refresh_skipped` operational-log warning, instead of a warning
  every 30 s for as long as it lasts (AGENT-302). It is reported again
  once a day while it lasts, and at once if it recurs after a refresh
  got a client.
- Under `fail_open`, a streamed event too big to judge no longer
  releases the text held before it unscanned (AGENT-273). That text is
  judged first, so a credential that arrived too small to trigger a
  scan is redacted, or blocks under `on_hit: block`, before anything
  goes out.
- A streamed response the upstream breaks off sends nothing more of
  what inspection holds; the agent gets the error (AGENT-273). Before,
  the held text was released first. A stream the agent leaves no longer
  judges the half event it was cut in, which under `fail_closed` wrote
  a false `inspection_error` block row.
- A credential in a streamed response behind a second level of JSON
  escaping (tool arguments are JSON in a JSON string, so `g` can arrive
  as an escaped `\u0067`) is found and redacted (AGENT-315). Before,
  streams were unescaped one level only, and such a credential was
  forwarded; request and buffered response bodies already caught it.
- The reference inspection sidecar's unit orders itself before
  `locksmith.service` (it named `locksmithd.service`, which is not the
  installed unit) and sets `HF_HUB_OFFLINE=1` to match its
  `PrivateNetwork=yes` (AGENT-278). The docs now say that a sidecar hit
  under `on_hit: redact` blocks the body.
- A rate-limit change that is stored but cannot be loaded into the
  proxy returns 503 `rate_limits_not_applied` and is logged, instead of
  `rate_limits_unavailable`, which said the write had failed
  (AGENT-272). A database error while looking up the route now returns
  503 instead of 404 `route_not_found`, and the audit row's `previous`
  limit is read in the same transaction as the write.
- Legacy `tools` credentials written as `"${VAR}"` or `"Bearer ${VAR}"`
  are copied into the database at startup, for tool names it does not
  already have (AGENT-299).
  Before, the text was expanded when the file was read, so these tools
  were skipped, and a `from_env` `prefix` was dropped, so a
  `prefix: "Bearer "` credential reached the upstream without `Bearer `.
  `Bearer` on the `Authorization` header now becomes a bearer
  credential. Any other prefix or text is not copied, and the daemon
  logs a warning for each tool it skips.
- A failed health probe no longer marks a loaded broker down
  (AGENT-310, AGENT-312, AGENT-314). A probe the broker fails is retried
  10 s after it started, and the route answers 503 `backend_unavailable`
  only when two retries in a row fail too, so about 20 s of slowness is
  absorbed. Broker up/down transitions are now also written to the
  daemon's log, not only to the operational log.
- A PEM private key whose body runs past 8 KiB is redacted whole
  (AGENT-270, AGENT-309). Escaped keys inside JSON reach that size.
  Before, only its first 8 KiB were removed and the tail was forwarded,
  in a body or a streamed response; a stream now holds such a key until
  its last line, within `max_scan_bytes`. Scanning a body packed with
  `BEGIN` lines is linear again, not 8 KiB per `BEGIN`.
  A stream no longer releases a key at END text that ends a long
  header line (AGENT-311).
- Redacting a JSON body rewrites only the strings that held a hit
  (AGENT-270). Before, the body was parsed and re-serialized, which
  sorted object keys, rounded integers too big for 64 bits, and dropped
  all but the last copy of a duplicate key. A hit in a shadowed duplicate
  key is now redacted in place instead of blocking the request. A key
  redacted to a name its object also uses is numbered against every key
  in the object, and numbering stays linear in the number of keys.
- A failed broker health probe records why, as `health.cause` and in the
  `broker_down` log: `unexpected_status`, `unreachable`, or the egress
  refusal (`egress_proxy_unconfigured`, `upstream_client_unavailable`)
  when the broker may not be reached (AGENT-269). Before, a proxied
  broker with no egress configured showed down with no reason.
- The egress policy no longer lists proxied `infra` registrations, which
  no path calls (AGENT-269); listing them only widened the allowlist.
  OAuth bootstrap and device login now refuse an infra registration (400
  `not_oauth_registration` / `device_login_unsupported`), since no path
  uses its session (AGENT-302).
- OAuth bootstrap takes the token endpoint and the egress from the same
  serving registration (AGENT-302). Before, an edit to the route while a
  bootstrap was in flight could send the new endpoint's token call under
  the old egress.
- An OAuth route's token calls (bootstrap, device login, inline and
  background refresh) now take the route's egress (AGENT-269). Before,
  they always connected directly, so a `proxied` OAuth route's token
  endpoint bypassed the egress proxy under `pipelock`, and a site with no
  egress configured still reached it. The egress policy now lists the
  token hosts of proxied OAuth routes and of the agent bindings that
  select them. **Under a Pipelock allowlist, add those token hosts before
  upgrading**: the `token_url` of every proxied OAuth route and of every
  agent binding that selects one (often the provider's auth host rather
  than its API host). The background refresh runs at startup, and a
  refresh, bootstrap or device login refused at the proxy leaves the
  session `reconnect_required`: sign in again with a device login, which
  replaces it in place, or revoke it locally (`locksmith oauth revoke`)
  and then bootstrap. Token calls trust
  `tls.upstream_ca_bundle` like routes do, and no longer follow
  redirects, which could have resent a refresh token to another host.
- `locksmith egress policy --pipelock` writes the allowlist with a YAML
  emitter, so a host can no longer break or extend the document
  (AGENT-269). A registration read failure behind the policy's 503
  `registrations_unavailable` is now logged. With `egress.mode: external`
  and `egress_proxy` both set, the daemon warns at startup that the proxy
  is ignored.
- A PEM private key's last line, with no `END` line in reach, is kept when
  a raw non-ASCII character (a `”` written by a UTF-8 encoder) or a
  control character follows it (AGENT-270). Before, that line was
  forwarded under `redact`, while the same key with the quote escaped as
  a `\u` escape was redacted whole.
- A PEM private key with no `END` line in nested tool arguments is read
  with every JSON escape decoded, at any depth (AGENT-270). Tab
  indentation written as `\t` or `\u0009` no longer ends the key, and a
  last key line followed by a tab, `.`, `!`, `?`, `&`, `>` or `|` is kept.
  Before, each escape needed its own rule, and a missing one forwarded the
  rest of the key under `redact`.
- A PEM private key with no `END` line in nested tool arguments is no
  longer cut short by any `\u00XX` escape of a base64 character, or by a
  line break written as `\u000A` (AGENT-270). Before, only `\/` and
  `\u002B`/`\u002F` were read, so an encoder that escaped other characters
  left the rest of the key to be forwarded under `redact`.
- A PEM private key with no `END` line in nested tool arguments is no
  longer cut short by an escaped `/` or `+` in a line (`\/` from PHP and
  json-c, `\u002B` from .NET), which forwarded the rest of the key under
  `redact` (AGENT-270). An indented blank line after `Proc-Type`/`DEK-Info`
  no longer ends the key, and a last key line followed by a space or
  punctuation is kept.
- A PEM private key with no `END` line is now redacted whole when its
  line breaks are escaped (`\n` in a JSON string, as in tool arguments),
  indented, or followed by trailing spaces, and its last line runs into a
  closing quote (AGENT-270). Before, only the `BEGIN` line (or the first
  lines) matched, so `redact` could forward the key body.
- A key escaped inside JSON nested in a JSON string (`"{\"k\":\"\\u0067hp_…\"}"`)
  is now found in buffered bodies (AGENT-270). The raw view was unescaped
  once, which left the inner escapes; it is now unescaped up to four more
  levels. Under `redact`, such a hit blocks if it is still there after
  the rewrite. Streamed responses still unescape one level.
- `dlp` finds two more encoded credentials (AGENT-270). A base64 run with
  letters glued to its start (`token<base64>`) is decoded at each
  alignment, so the prefix no longer garbles it, and the decoded bytes are
  read lossily so the garbage prefix can't hide what follows. A JWT whose
  payload is over 4096 characters is matched as its header and first 4097
  payload characters, where before it was not matched at all.
- A redaction that can't remove every match now says so in its audit row
  (AGENT-270): the block carries `redaction_incomplete: true`. That covers
  a match in the path or query, a body that isn't UTF-8, and a match still
  found when the rewritten body is scanned again. A scanner that fails
  during that rescan still blocks, even under `fail_open`, but the row now
  records `details.error: "rescan <scanner>: <why>"` instead of nothing.
- A compressed or NDJSON reply can no longer slip past a response policy
  that redacts or blocks (AGENT-270). Such a policy now defaults to
  `on_error: fail_closed`. Inspected routes also ask the upstream for
  `Accept-Encoding: identity` instead of sending no header, which RFC 9110
  reads as accepting any coding. Policies that only flag, and request
  policies, are unchanged.

  **Upgrade note.** On a route whose response policy sets `on_hit: redact`
  or `block` without `on_error`, every reply the policy can't judge is now
  refused instead of forwarded unscanned: 502 `inspection_blocked` before
  the body starts, or an error event that ends a server-sent event (SSE)
  stream. That covers:
  - a compressed or NDJSON reply;
  - a reply over `max_scan_bytes` (1 MiB by default);
  - a scanner error or timeout, including a sidecar that is down, answers
    with an error or misses its `timeout_ms`;
  - an SSE stream that uses a sidecar scanner (sidecars can't scan streams),
    and an SSE event the scanner can't follow (oversized, unparseable,
    or held text past the cap).

  Set `on_error: fail_open` on the policy to keep the old behaviour. It
  covers all of these at once, including the compressed-reply bypass.

- Agents can call an upstream's root: `/api/<route>/` now forwards to
  `<upstream>/` and `/api/<route>` to the upstream URL exactly, query kept
  (AGENT-290). Before, the router answered 404 with an empty body and never
  forwarded, so APIs served at the root (the seed `duckduckgo` route) or at
  the base URL could not be used. `Location` and `Link` targets that point at
  the bare upstream are now rewritten to `/api/<route>` as well.
- Edge site files accept a component `closed = [port, ...]` list,
  rejected for every source (for example an admin listener). Before, a
  port could only be opened to CIDRs or left unfiltered, so a rendered
  Locksmith with admin HTTPS on 9201 was reachable from the whole zone.
- `PUT /admin/operator/rate-limits/{route}` refuses a native MCP or
  `infra` registration with 400 `route_not_limitable` (AGENT-272). Only
  the `/api/*` proxy enforces limits, so such a limit was listed and
  audited but never applied. Limits already stored for those routes stay
  listed and still do nothing; delete them.
- Rate-limit reloads run one at a time (AGENT-272), so two admin writes
  close together can no longer leave the proxy enforcing the older table
  until the next write.
- Changing a route's `max_concurrent` keeps counting requests already in
  flight (AGENT-272). It used to start a fresh count, so raising the cap
  admitted a full new batch on top of the running ones and lowering it
  admitted new work at once.
- A request can no longer leave a route's upstream base path
  (AGENT-286). The path is decoded before the upstream URL is built, and
  the URL parser resolves dot segments and backslashes, so
  `/api/<route>/%2e%2e/other` reached `other` on the same host with the
  route's credential. The path is also judged as a normalising upstream
  reads it (decoded again, `;` parameters dropped, `\` as `/`), so
  `..%252F` and `..;/` are refused too. Such a request gets 400
  `upstream_path_escape` and an audit row, and nothing is sent.
- Request inspection judges the path and query the way the upstream
  will read them (AGENT-270). axum decodes the path once before Locksmith
  builds the upstream URL and the upstream decodes it again, so a
  double-encoded `%2543` passed the scanners as `%43` and arrived as `C`.
  Every decoding of the path is now judged, from both the request and the
  upstream URL as reqwest parses it. That parser deletes tab and newline
  (`CAN%09ARY` left as `CANARY`) and turns a decoded `%3F` into a query,
  so neither can split a match any more. The query is also judged with
  `+` kept literally. An inspection config that does not compile now stops
  startup instead of silently serving every route uninspected.
- Injection scanning folds mathematical alphanumerics (bold, italic,
  script, double-struck and similar letters and digits, plus the
  letterlike symbols in that range) to ASCII, and drops combining marks,
  so `𝐢𝐠𝐧𝐨𝐫𝐞` and `i\u0301gnore` read as `ignore` (AGENT-270).
- Keep the sealing keys away from processes running as Locksmith's own
  user (AGENT-285). A classifier sidecar shares that user so Locksmith
  can check the socket's peer uid, which also let it read
  `/proc/<pid>/environ`, where the sealing keys are.
  - `locksmithd` marks itself non-dumpable on Linux before its runtime
    starts, which also disables its core dumps.
  - The `op read` child it runs for `op_*` credentials gets only a
    minimal environment (`PATH`, `HOME`, locale, proxy, `XDG_*` and
    `OP_*`), without the sealing keys or env-backed upstream
    credentials. It still needs the 1Password token, so the guide
    recommends `stored_*` credentials next to a sidecar.
  - Edge units exec their command directly, with `Environment=` lines
    instead of an `/usr/bin/env` wrapper. The guard refuses to start a
    component with an environment file unless its executable is
    root-owned and execute-only (mode 0711), which makes the process
    non-dumpable from exec. **Upgrade note:** reinstall `locksmithd`
    with `install -m 0711` and re-render the edge units. The guard
    covers edge units only; other deployments that run the reference
    sidecar must install `locksmithd` that way themselves, as
    `dist/inspector/README.md` now says (AGENT-288).
- The edge model installer (`dist/edge/install_model.py`) now refuses a
  cache under a directory that is not root-owned or is group- or
  world-writable, so a service-owned parent cannot be used to swap the
  weights. It also makes the cache readable whatever the installer's
  umask. The guide and example site now keep the cache in
  `$R/models/<component>` and start the inspector component (AGENT-285).
- Route traffic on `egress: proxied` routes no longer goes direct when
  the egress proxy is missing or broken (AGENT-259). Before, an unset
  `egress_proxy`, a URL that didn't parse, or a client that failed to
  build each silently sent the route straight to the internet. Now
  `egress_proxy` must parse at config load, and a proxied route with
  nothing enforcing egress answers 503 `egress_proxy_unconfigured` and
  writes an `egress_unenforced` security audit event. OAuth token
  refreshes and logins still connect directly; that is tracked
  separately.

  **Upgrade note:** most seed catalog routes are `egress: proxied`. A
  deployment with no `egress_proxy` (a development or standalone
  install) now gets 503 on them. Set `egress_proxy` to enforce egress
  through a proxy, or `egress: { mode: external }` to keep connecting
  directly when the surrounding infrastructure enforces egress.
- Locksmith no longer sends traffic to a proxy set in its environment
  (AGENT-277). reqwest honours `HTTP_PROXY`, `HTTPS_PROXY` and
  `ALL_PROXY` for any client built without an explicit proxy, so
  `egress: direct` routes, `proxied` routes under `egress.mode:
  external`, OAuth logins and refreshes and CRL fetches all followed a
  proxy the daemon's environment named, credentials included. Every
  client the daemon builds now ignores those variables; only
  `egress_proxy` routes traffic through a proxy.

  **Upgrade note:** a deployment that set `HTTPS_PROXY` on `locksmithd`
  so OAuth or CRL calls could leave a proxy-only network must now allow
  the OAuth token and device-authorization hosts and the CRL
  distribution points directly. Routes that need a proxy use
  `egress: proxied` with `egress_proxy`.
- The proxy no longer follows upstream redirects. A followed redirect to
  another host carried the route's key with it when the key used a
  custom header name such as `x-api-key`, so an upstream with an open
  redirect could hand the key to any host. The agent now receives the
  3xx: a `Location` on the route's own upstream is rewritten onto the
  route as before, and any other `Location` is left for the agent to
  fetch directly, without Locksmith's credential.
- Revoking an agent now removes its account bindings, stashed backend
  bindings, grants and native grant sets in the same write, and audits
  their counts (#157). Before, they stayed behind and could not be
  listed or removed once the agent was revoked. `locksmith agent
  prune-revoked [--dry-run]` (`POST /admin/operator/revoked-agents/prune`)
  removes what earlier revokes left: it names agents and routes, never
  credential values, and audits counts only.
- Operator grant and binding changes are now audited (AGENT-253).
  `agent modify` rows had empty details, and `agent set-credential` /
  `unset-credential` wrote no row at all, so after the fact nobody could
  tell who granted a route or switched an agent's account. `agent_modify`
  now records each changed field before and after, and binding changes
  write `agent_credential_set` / `agent_credential_unset` naming the route
  and the binding kind, never a credential value.

### Added

- `locksmith agent set-credential <id> <reg> --stored-header-stdin
  [--header <Name>]` (AGENT-325) seals a per-agent value read from stdin
  that is sent bare in a header: `--header`, or else the route's own
  header. A route that names no header refuses it without `--header` (400
  `invalid_stored_credential`) rather than sealing a bearer. The admin API
  takes this as `"stored_header": true` on the per-agent `credential` PUT.
  Before, stdin took only bearers (`--stored-bearer-stdin`), so an API
  that wants a bare key, such as Linear's `Authorization: <key>`, had no
  CLI path to a stored value.
- Edge packaging in `dist/edge/` (AGENT-258). It runs Locksmith, and
  optionally Pipelock and a classifier sidecar, as hardened systemd
  services in Incus system containers. The tools, all standard-library
  Python, read a site file you keep in your own private repository:
  - `incus.py` prints reviewable commands for stopped containers, each
    with its own state volume.
  - `render.py` writes inactive units, an ingress nft table and a root
    guard that refuses to start a service without its custody receipt.
  - `install_model.py` downloads a pinned classifier model into an
    offline Hugging Face cache. Gated models such as PromptGuard 2 are
    fetched under your own HF token, which never reaches argv, disk or
    the CDN.
  See [edge packaging](docs/operator/edge-packaging.md).

- Per-agent, per-route rate limits (AGENT-266). `locksmith rate-limit
  set <route> --rpm N [--concurrent N] [--agent A]` (`PUT
  /admin/operator/rate-limits/{route}`) sets a route default that applies
  to each agent separately, or one agent's override; `list` and `unset`
  complete it. Over the limit the proxy answers 429 `rate_limited` with
  `Retry-After` before anything is sent upstream; a concurrency slot is
  held until a streamed body ends. Changes apply live and are audited.
  Migration 0027 adds the `rate_limits` table.
- Content inspection (AGENT-262). An `inspection:` config block gives a
  route request and response scanners with a verdict on a hit (`pass`,
  `flag`, `redact` or `block`) and a choice of failing open or closed.
  Request bodies, paths and query strings are scanned before anything
  is sent upstream, and buffered responses before anything reaches the
  agent. Raw bytes are scanned as well as parsed JSON, so invalid UTF-8,
  unparseable JSON and duplicate keys don't hide a match. Server-sent
  event streams are scanned as they pass (AGENT-265) through a sliding
  window, so a match split across deltas is found: under `flag` each
  event is forwarded at once, under `redact` or `block` events are held
  until they are safe (about 8 KB of text with the built-in scanners)
  and a block ends the stream with a protocol-shaped error event.
  Newline-delimited JSON streams are not scanned. `inspection.sidecars`
  (AGENT-254) adds scanners behind a Unix socket, named
  `sidecar:<name>`, served by a process running as Locksmith's own user;
  `dist/inspector/` has a reference PromptGuard 2 / CodeShield sidecar
  (weights not shipped). Each inspection
  that finds, skips or fails something writes an `inspection_*` security
  audit event carrying rule ids and SHA-256 hashes, never the matched
  text. Scanners: `literal:<text>` and `dlp` (AGENT-263), Locksmith's
  own credential rules (AWS, GitHub, Slack, OpenAI, Anthropic, Google,
  Stripe, PEM private keys, JWTs, bearer tokens, one level of base64)
  plus a flag-only entropy heuristic, and `injection` (AGENT-264),
  prompt-injection phrasing matched after folding zero-width
  characters, look-alike letters and case; it defaults to `flag`. See
  `docs/development/inspection.md`.
- `egress.mode` (AGENT-261) declares who enforces `egress: proxied`
  routes: `pipelock` (every proxied route uses `egress_proxy`, which is
  then required; the default whenever `egress_proxy` is set) or
  `external` (the surrounding infrastructure, such as a mesh egress
  policy, enforces egress and proxied routes connect directly). The
  daemon logs the mode at startup.
- `locksmith egress policy [--pipelock]` (`GET /admin/operator/egress/policy`)
  publishes the hosts reached by proxied routes, grouped by host with the
  routes behind each, and can render them as a Pipelock `api_allowlist`
  (AGENT-137).
- `locksmith rekey-credentials --database DB --old-key-file F --new-key-file F`
  re-keys stored credential values offline: every row is resealed under the
  new credential sealing key in one transaction, or none is if the old key is
  wrong. Keys are read only from owner-only files. This is the stored-key
  rotation path, and lets a database copy run under its own key.

### Changed

- The seed catalog (2.3.0) no longer ships the `lf-scan` sidecar
  (AGENT-256); inline inspection replaces it. Removing a seed entry never
  deletes a row, so a deployment that seeded it keeps the registration.
  `locksmith infra delete lf-scan` disables a seeded row (it stays
  listed); to remove it entirely, `locksmith infra put` it first so it
  becomes operator-owned, then delete it.
- Agents now receive upstream redirects instead of their final response.
  Redirects to the route's own upstream point back at Locksmith, so
  clients that follow redirects (`curl -L`, most HTTP libraries) see no
  difference. Redirects to another host, such as GitHub tarball and log
  downloads to signed storage URLs, must be fetched by the agent over its
  own egress; an agent that can reach the network only through Locksmith
  can no longer complete them. The agent's client must drop its
  Locksmith bearer (`Authorization`) on a host change, as standard
  clients do. On routes with response controls a redirect is returned
  with an empty body.

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
- Broker hardening (#159). Hop-by-hop, framing and Locksmith-managed
  header names are refused as a broker identity header (400
  `invalid_broker`) and as any credential header (400 `invalid_metadata`).
  An agent's `X-Locksmith-Agent` never reaches a broker, even when the
  identity header is renamed or omitted. A broker key that cannot be
  materialized is no longer reported as the broker being down: the probe
  is skipped, `broker_key_unresolved` is logged, and requests fail with
  503 `credential_unresolved`. Health probes no longer follow redirects.
  The proxy and the prober share one key resolver. A repeated attribution
  header is flagged `broker_account_invalid`. A broker `put` without
  `auth` keeps the key only for the same destination (400
  `invalid_broker` otherwise) and never undoes a concurrent rotation (409
  `broker_key_changed`). Selection and key failures are reported before
  a down broker.
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
  [refusal and lifecycle boundaries](docs/operator/oauth-capability-proof.md).

- Add a [nonpublishing native candidate lane](docs/development/native-validation.md)
  with bounded build, smoke and artifact checks for four targets; local fixtures
  do not establish platform execution or release publication.

- Decode documented Slack workspace display labels in declared identity checks
  while retaining exact observed IDs, bot refusal and token echo validation;
  expose [closed identity diagnostics](docs/operator/slack-identity-diagnostics.md).

- Add [declared custom OAuth contracts](docs/operator/custom-oauth.md) for exact scopes, independently verified user/workspace or service-principal identities, none/confidential clients and explicit Slack response variants. Existing named contracts remain unchanged. Migration 0022 preserves custody and sequence highwaters; old binaries refuse the new schema.

- Report [closed Slack token metadata reasons](docs/operator/slack-token-diagnostics.md)
  through the existing attempt/refresh status path. Missing, null, wrong-type and
  conflicting metadata remain refused without provider values or token hashes.
  Acceptance, identity/scope checks and custody are unchanged; reason enums are
  additive, with no migration. Historical broad failures remain undiagnosed.

- Permit an absent Slack response issuer only at the dedicated, issuer-distinct
  `/oauth/callback/slack` redirect, with actual Host/path checked against sealed
  attempt state before claim. Supplied issuer checks and legacy/Linear mandatory
  issuer behavior remain. [Callback upgrade](docs/operator/slack-callback.md)
  requires a new client generation and explicit reactivation; no migration or
  automatic custody rebind. Offline TLS controls do not establish live acceptance.

- Separate the fixed Slack OAuth resource `https://mcp.slack.com` from MCP
  transport `https://mcp.slack.com/mcp` across activation, custody checks and
  native sessions. The old real-kind `/mcp` resource now refuses explicitly;
  [deliberate binding repair](docs/operator/slack-oauth.md#renewal-retirement-and-upgrade)
  is required. Existing Linear and local fixture behavior remains. Offline
  receiving evidence does not establish live Slack confidential-S256 acceptance.

- Add an explicit [confidential Slack user profile](docs/operator/slack-oauth.md)
  through owner-bound sealed client/token custody and customer definition activation.
  S256/client authentication, exact identities/scopes, finite tool authority and
  deliberate refresh repair are exercised against an invented TLS receiver.
  Migration 0021 preserves custody/highwater and permanently retires client generations.
  Preserve closed deadline/HTTP diagnostics; no live provider acceptance is claimed.

- Add explicit [finite-v2 native contracts](docs/operator/native-contract-policy.md)
  for supported customer None/bearer/OAuth sources through existing review/grants.
  Customer registrations can explicitly select names after the same complete
  bounded catalog scan, with declared omissions and no early publication.
  Preserve bounded inert metadata, scalar default annotations and up to 64 input
  enum values. Open-empty input requires a digest-bound empty-arguments restriction
  with a separately labeled callable schema. V1 bytes/output rules remain; old
  readers refuse the new marker. Migration 0020 permits dedicated definition policy
  activation/reset while preserving immutable pins and active configuration; prior
  schema-19 daemons refuse the newer database. No provider acceptance or timeout change.

- Add a fixed [hosted Linear OAuth profile](docs/operator/hosted-linear.md)
  and an explicit local fixture kind through existing owner custody, refresh,
  native selection and finite grants. Hosted observation scans a bounded complete
  catalog and retains only explicitly selected original contracts with omission
  counts; unsupported selected schemas refuse. Public callback authority is
  separate from the loopback TLS bind. Migration 0019 preserves custody/highwater
  and refuses prior daemons. Live shipping provider adoption remains separate.

- Connect the [local customer MCP journey](docs/operator/customer-mcp-journey.md)
  from definition promotion through account selection, finite review/grants,
  ordinary task discovery and deliberate repair. Clarify that controlled refresh
  invalidates existing native authority without creating grants. Live-provider
  acceptance remains open.

- Add deliberate CAS-controlled activation/deactivation for immutable `local.*`
  customer definitions: explicit None, live StoredBearer or configured controlled
  OAuth. Import/creation/promotion create no account or grant. Full authority
  repair follows real transitions; current exact-state retries only resync.
  Migration 0018 refuses older whole-daemon startup. Builtin providers and full
  readiness remain open. See [setup and recovery](docs/operator/integration-definitions.md).

- Add deliberate owner-bound [controlled OAuth native selection](docs/operator/native-oauth.md),
  finite preparation and standard/compact dispatch through the existing admission path.
  Refresh/version or trust changes require renewed preparation and a fresh session;
  reconnect requires reselection. Access-only materialization preserves optional refresh.
  Migration 0017 refuses older whole-daemon startup; hosted providers remain unproved.

- Add manual owner-bound controlled refresh and explicit fresh-consent repair.
  Migration 0016 commits pending uncertainty before I/O and exact current custody
  before success, preserving optional expiry/scope and claimed refresh retention.
  Status/revisions and the [JSON contract](docs/operator/oauth-account-response-v1.schema.json)
  expose pending/reconnect state. Legacy kind barriers remain; no automatic refresh,
  hosted provider acceptance or agent/native authority. Prior schema-15 binaries
  refuse upgraded state; restore only a full prior snapshot under recovery rules.

- Add [controlled operator consent](docs/operator/oauth-consent.md) with
  public-ID ownership, sealed `connected_unbound` custody, strict twin identity
  checks and revision-checked disconnect. Migration 0015 preserves legacy custody;
  older binaries refuse the new schema/config. Hosted provider acceptance and
  native OAuth activation remain outside this increment.

- Document and exercise [sealed-state recovery](docs/operator/sealed-state-recovery.md):
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
  [skill reference](docs/reference/skill-reference.md). Guidance reads
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
  existing bytes/digests. See [operator guidance](docs/operator/native-context.md).
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
  dispatch. See [agent workflow](docs/agents/native-mcp.md) and
  [implementation/verification](docs/development/native-dispatch.md). Full206 and
  provider/compact acceptance remain open; bounded fixed context is above.

### Native tool preparation

- Add operator-only observe/inspect/review/finite grant replacement for manual
  native None and sealed-bearer accounts, with matching strict CLI/API. Stage A
  initially retained empty lists and denial; stage B above adds reviewed calls. See the
  [workflow, limits and upgrade](docs/operator/native-tool-review.md).
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
  before daemon return releases database ownership. See [recovery and upgrade](docs/operator/oauth-recovery.md).
  This is bounded local AGENT-205 only; consent204, provider policy/live T14
  and full205 acceptance remain open.

### Integration definition authoring

- Add strict immutable definition import/get and create-only disabled native
  instances through matching operator CLI/API. Pins include exact revision,
  content digest and descriptive auth profile; no provider request, credential,
  account selection or authority is created. Candidate reference/customer
  examples use the same validation. See [operator workflow](docs/operator/integration-definitions.md).
- Migration0012 preserves existing state and makes older binaries refuse the
  upgraded database. Derived rows reject general edits/enable; credential
  attachment and sealed storage now commit together, including rollback on
  pinned replacement. See [upgrade and limits](docs/changes/integration-definitions.md).
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
  owns each database. See [setup](docs/operator/native-mcp.md),
  [wire contract](docs/agents/native-mcp.md) and
  [backup, recovery and limits](docs/changes/native-mcp.md).

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
  Follow [recovery/backup/rollback guidance](docs/operator/oauth-recovery.md).
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
- [Connector onboarding change notes](docs/changes/connector-onboarding.md)
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
- A focused [operator onboarding recipe](docs/operator/connector-onboarding.md)
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
  Follow [the migration guide](docs/concepts/migrating-account-bindings.md).
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
- See [HTTP grant and activation changes](docs/changes/explicit-http-grants.md)
  for saved-but-failed activation repair, next-admission boundaries and limits.
  Original local synthetic acceptance is historical. Live-provider
  compatibility is not claimed.
