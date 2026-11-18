# Content inspection

Locksmith terminates every agent request and makes the upstream call
itself, so it sees plaintext in both directions without TLS
interception. The inspection pipeline (`src/inspection/`) uses that
position to scan brokered traffic: requests (body, decoded path and
query) before anything leaves, and responses before anything reaches the
agent. Headers are not inspected in either direction: request headers
(Locksmith strips the agent's credential headers rather than scanning
them) and response headers both pass unscanned. This implements the D-18
inspector design (AGENT-150) in-process, with ML scanners in a same-UID
sidecar (see [Sidecars](#sidecars)).

## Policy

Policy is per route, in the `inspection:` config block (restart to
change):

```yaml
inspection:
  routes:
    - route: search              # registration or config tool name
      request:
        scanners: [dlp]
        on_hit: block            # pass | flag | redact | block
        on_error: fail_closed    # fail_open | fail_closed
        max_scan_bytes: 1048576
      response:
        scanners: [injection]    # on_hit defaults to flag
```

| Setting | Request default | Response default |
|---|---|---|
| `on_hit` | `block` | `flag` |
| `on_error` | `fail_closed` | `fail_open`; `fail_closed` when `on_hit` is `redact` or `block` |
| `max_scan_bytes` | 1 MiB | 1 MiB |

A response policy that redacts or blocks fails closed unless `on_error` says
otherwise, so a reply it can't judge doesn't pass unjudged. Under
`fail_closed`, a buffered reply that is compressed, oversized or hit by a
scanner error or timeout is refused with 502, as is a compressed or NDJSON
stream and any SSE stream on a policy with a sidecar scanner, since
sidecars don't scan streams: that is known before anything is sent. An SSE
stream that hits a scanner error, an event or held text past
`max_scan_bytes`, or anything else the scanners stop being able to follow
part-way through has already sent its headers, so under `fail_closed` it
ends with an error event instead. Under `fail_open` each of these passes,
audited.

Unknown scanner ids, an empty scanner list and a route listed twice fail
config load.

## Scanners

| Id | Direction | What it matches |
|---|---|---|
| `literal:<text>` | either | An exact string, such as a canary token. |
| `dlp` | either (meant for requests) | Credentials and secrets; rules below. |
| `injection` | either (meant for responses) | Prompt-injection phrasing; rules below. |

### `dlp` rules

Locksmith's own curated set (AGENT-263), not a port of another tool's.

| Rule | Matches |
|---|---|
| `aws_access_key_id` | `AKIA` / `ASIA` plus 16 upper-case alphanumerics |
| `github_token` | `ghp_`, `gho_`, `ghs_` and `github_pat_` tokens |
| `slack_token` | `xoxa-`, `xoxb-`, `xoxp-`, `xoxr-`, `xoxs-` |
| `openai_key` | `sk-` and `sk-proj-` keys with digits and both letter cases |
| `anthropic_key` | `sk-ant-` keys |
| `google_api_key` | `AIza` plus 35 characters |
| `stripe_live_key` | `sk_live_` keys |
| `private_key` | A PEM private key: from the `-----BEGIN ... PRIVATE KEY-----` line through an `END` line within 8 KiB (or else through the base64 and `Proc-Type`/`DEK-Info` lines that follow, indented or not, and with JSON escapes at any nesting depth read as the characters they stand for (`\n`, `\t`, `\r`, `\/`, `\"`, and `\uXXXX` of an ASCII character), as in a key inside tool arguments; any other escape, a control or non-ASCII character, a quote, bracket or common punctuation ends a key line, and the base64 before it is kept as the key's last line), so `redact` removes the key, not just its header. The key is followed to its last line however long it is (AGENT-309); only the two lines after `BEGIN` can be headers. A key joined onto its `BEGIN` line with spaces (headers and base64 words on one line) is covered to its last base64 word (AGENT-311). That line counts as key when it is one base64 word (the key's first line), or when it holds a base64 word of at least 16 characters among header words (holding `:` or `,`) and shorter base64; header words alone may be followed by the RFC 1421 blank line. Prose after a `BEGIN` line is mostly left alone, but a long word in it can be taken for key and redacted with the words around it. In a stream, a key still arriving is held until its last line, within `max_scan_bytes` |
| `jwt` | Three base64url segments whose header decodes to JSON with `alg`. A payload over 4096 characters is matched as the header and the payload's first 4097 characters, which is enough to remove the token |
| `bearer` | The token after `Bearer`: 40+ characters, at least 3 bits/char |
| `base64:<rule>` | A 24 to 4096 character standard-base64 run whose decoded text (one level, at each of the four alignments so letters glued to the run's start don't hide it) matches a rule above; the span is the whole run |
| `entropy` | A 32 to 128 character token run at 4.5 bits/char or more that no other rule covers. Flag-only |

Each rule has a fixed maximum match length; the scanner's
`max_match_len` is the largest (`private_key`, 8,239 bytes). Longer runs
are not matched, so a 50 KiB inline image is neither decoded nor flagged.
The length bounds the regex match; a `private_key` hit then grows over
the key's lines, which can make it longer.

### `injection` rules

AGENT-264. Text is folded first: invisible format characters (zero-width
and joiners, soft hyphen, bidi controls, invisible operators, fillers,
variation selectors, TAG characters) and combining marks are dropped,
each letter, fullwidth ASCII character, parenthesized letter and
mathematical digit is replaced by its compatibility decomposition (NFKD,
which folds fullwidth, mathematical, circled, superscript and accented
letters and Roman numerals; spaces in an expansion and an enclosed
form's parentheses are dropped), Cyrillic, Greek, small capital and
other look-alikes NFKD leaves alone fold to ASCII, each whitespace run
becomes one space, and case is lowered. Symbols and numbers (`™`, `²`,
`½`) keep their own form. An expansion more than one byte longer than
its character (U+FDFA is eighteen characters) is not used, so folded text
stays within about 1.5 times the input. A letter the fold makes can glue
onto a phrase's first or last word and break its `\b` (`instructionsé`,
a flag or `ℹ️` before `Ignore`), so when a text holds a character this
fold treats differently from the fold before AGENT-315 (Cyrillic, Greek,
fullwidth and mathematical letters and Latin-block marks only), that
stricter fold is matched as well and the hits are merged. A text holding
a symbol letter (a flag, `ℹ`, a circled or squared letter) is also
matched with the full fold but those symbols kept as themselves, so a
glued emoji cannot hide a phrase spelled with a trick only the full fold
reads (`ígnore previous instructions🇺🇸`). Hits are reported at their
original byte offsets, extended over combining marks on the last letter,
so `redact` removes what was really sent.

Rules: `ignore_instructions`, `disregard_above`, `role_reassignment`
(`you are now DAN`, not `you are now ready`), `system_prompt_label`,
`chat_template_token` (`<|im_start|>`, `[INST]`, `<<SYS>>`),
`system_override`, `mode_switch`, `do_anything_now`, `new_instructions`,
`reveal_prompt`, `no_restrictions`, `from_now_on`, `system_tag`,
`exfiltrate` (`send the credentials to`), `conceal_from_user` and
`hidden_command`. A phrase hit covers its padding, so `redact` removes the
whole phrase. Five or more invisible characters in a row are also
reported as `invisible_run`, and any run of TAG characters (U+E0000 to
U+E007F, used to smuggle invisible ASCII) as `tag_characters`; both
cover the whole run. `max_match_len` for this scanner bounds folded text,
so a streaming window must carry that much folded text.

A phrase list catches copied, common attacks, not novel ones. A policy
whose only scanner is `injection` defaults to `on_hit: flag` in both
directions; set `on_hit` to block or redact deliberately.

Each scanner reports hits as byte spans plus a rule id, and declares the
longest match it can report (`max_match_len`), which streaming uses to
size its overlap. A rule can be flag-only (an entropy heuristic): its hits
never produce more than `flag`, whatever `on_hit` says.

## Verdicts

The strongest verdict over all hits wins (`block` > `redact` > `flag` >
`pass`):

- `pass`: nothing found; no audit row.
- `flag`: forwarded unchanged; one audit row.
- `redact`: each matched span is replaced with `[REDACTED:<scanner>]`
  and the body is forwarded.
- `block`: nothing is forwarded. A request gets 403, a response 502, both
  with error code `inspection_blocked`.

## What is scanned

- **JSON bodies** (a content type containing `json` that parses) are
  scanned string by string, object keys included and every copy of a
  duplicate key, after JSON unescaping. A redaction rewrites only that
  string or key in place; every other byte of the body is forwarded as
  sent, so key order, number spelling (integers too big for 64 bits
  included) and whitespace are unchanged. A key redacted to a name the
  object already uses, or uses later, is numbered (`[REDACTED:dlp]#2`) so
  no value is lost.
- **Other UTF-8 bodies** are scanned as one text.
- **The raw bytes** of every body are scanned too, read as lossy UTF-8
  with JSON escapes resolved (and percent-decoded for
  `application/x-www-form-urlencoded`). This catches what parsing hides:
  a body that is not valid UTF-8, JSON that fails to parse (trailing
  bytes, deep nesting) with escapes inside, and form encoding. A hit
  found only this way can't be rewritten in place, so `redact` becomes
  `block` for it. JSON nested in
  a JSON string (tool arguments, say) keeps its own escapes after one
  pass, so the raw view is also unescaped again, up to four more levels,
  until nothing changes. A match in those deeper views blocks under
  `redact` only if it is still there after the rewrite (see below), so a
  key the rewrite removes, such as a PEM block whose `\n` the deeper view
  resolves, is still redacted. Streamed text is unescaped the same way,
  up to four levels past the event's own JSON decoding; a match found
  there is redacted where its escaped text lies, and the window keeps
  enough of the escaped text (and holds an escaped PEM key) as it would
  the plain form, within `max_scan_bytes` (AGENT-315).
- **The decoded path and query** of a request are judged the same way,
  never rewritten, even when the body itself is oversized or encoded.
  Credentials that legitimately ride in a URL (presigned
  `X-Amz-Credential=AKIA...`, a JWT query parameter) match `dlp` too, so
  such routes should not use `dlp` on requests or should set
  `on_hit: flag`.
- **A redaction that can't remove every match** becomes a block, and the
  audit row carries `redaction_incomplete: true`. That covers a
  redact-level match in the path or query (never rewritten, even when the
  body holds the same text), one only a raw view sees, a body that isn't
  UTF-8, and a match still found when the outgoing bytes (raw views, path
  and query) are scanned again after rewriting. That rescan is the only
  guard for copies the rewrite can't reach, such as `SEC%52ET` in a form
  body, so a scanner that fails during it blocks the body even under
  `fail_open`, and the row records `error: "rescan <scanner>: <why>"`.
- **Binary bodies** (not UTF-8) are scanned only through the raw view. With
  no hit they pass and are audited `inspection_skipped` with reason
  `not_text`, so uploads are not blocked by a text scanner.
- **Content-encoded bodies** (any `Content-Encoding` other than
  `identity`, such as gzip) can't be scanned as sent and could hide text,
  so they are audited `inspection_skipped` with reason `encoded` and
  follow `on_error`. On a route with a response policy, Locksmith replaces
  the agent's `Accept-Encoding` with `identity`, so a well-behaved upstream
  answers uncompressed.
- **Bodies over `max_scan_bytes`** are audited `inspection_skipped` with
  reason `oversize` and follow `on_error`: forwarded under `fail_open`,
  blocked under `fail_closed`. A large response is read only up to the
  limit; under `fail_open` the rest is forwarded unscanned, and the
  route's response controls (size cap, redaction) still apply to it.
- **Server-sent event streams** (`text/event-stream`) are scanned as they
  pass; see [Streamed responses](#streamed-responses).
- **Newline-delimited JSON streams** (`application/x-ndjson`,
  `application/jsonl`, `application/x-jsonlines`,
  `application/stream+json`) are not scanned. They are audited
  `inspection_skipped` with reason `streaming` and, under
  `on_error: fail_closed`, refused with 502 `inspection_blocked`.

Scanning runs on a blocking thread with a 5 second deadline; a scan that
misses it (`scan timed out`) or panics (`scan failed`) is an
`inspection_error` and follows `on_error`.

A request is scanned as the agent sent it, before Locksmith adds the
route's credential or any profile fixup, so Locksmith's own key is never
a match.

## Streamed responses

A server-sent event stream (AGENT-265) is parsed event by event (CRLF,
LF and lone CR line endings; one leading UTF-8 BOM is ignored, as clients
ignore it). As in a buffered body, every JSON string and every object key
in an event's `data` is scanned, aggregates as well as deltas; a redact
renames a key, numbering a name already taken. Empty strings are
skipped. Short texts found clean (ids, model names, keys) are remembered
for the stream and not scanned again. Data that is not JSON is scanned
as one string, and, when it holds a backslash, again with its escapes
resolved; a redact-level hit only that view shows blocks, since no
rewrite can reach it. Data shaped like JSON (starting with `{`, `[` or
`"`) that does not parse (a number out of range, nesting past the
parser's limit, a string left open), which a client may still decode,
follows `on_error` with or without escapes: under `fail_closed` the
stream is blocked. When JSON
repeats a key, the values the parsed view hides are decoded and scanned
too, since a client that keeps the first value reads them; a redact
re-writes the event from its parsed view, which drops them. A hidden
value is scanned within its event only, so under `fail_closed` an event
that repeats a key blocks the stream, and under `fail_open` it writes an
`inspection_hold_overflow` row.

A string complete in its own event (a snapshot) is scanned alone and
never waits for later text: every Responses event except a `*.delta`
(`response.created`, `.added`, `.done`, `response.completed` and the
rest), Anthropic `message_start`, `message_delta` and `message_stop`, a
chat chunk's fields outside a choice's `delta` (`logprobs`, Azure content
filter results, `usage`), and, within a choice, anything named as
protocol metadata (`type`, `id`, `object`, `model`, `role`,
`finish_reason`, `stop_reason`, `system_fingerprint`, `status`,
`item_id`, `call_id`, `response_id`, `obfuscation`, `service_tier`,
`instructions`), such as a delta's `role` or a tool call's `id`. Only
fields later events extend go to a window: a chat or completions
choice's `delta` and `text`, a Responses `*.delta`, an Anthropic block's
text, thinking and tool input, and the opening text clients start them
from (`content_block_start`, a Responses `.added` part's text or refusal,
or a call's arguments). An event a redaction rewrites loses its
`logprobs` (`null`, or `[]` where it is a list): its tokens, their bytes
and alternatives would spell the text the cut removed.

Each of those goes to the window of the output it belongs to, the way a
client rebuilds the stream: each chat choice and each tool call by its
`index` inside `choices`, each Anthropic content block by its `index`,
each Responses content part by `output_index` and `content_index`, each
reasoning summary by `output_index` and `summary_index`, and any other
Responses output (a call's arguments) by `output_index`. A stream's
protocol is fixed by its first protocol event, and only the indexes its
clients use for that event's type count, so an upstream cannot split one
output across windows by adding or varying others (a top-level `index` on
a chat chunk names nothing, and an empty `choices` on another protocol's
event changes nothing). An event naming another protocol, or whose event
name and `type` differ where either names a protocol event (the SSE
default name `message` names none), could be read two ways; and a snapshot
clients append deltas to (Responses `response.created` output, an
`output_item.added` item's content or summary, Anthropic `message_start`
content) carrying text, which real streams send empty, would split a match
from its deltas. Either way, under `fail_closed` the stream is blocked,
under `fail_open` an `inspection_hold_overflow` row is written. So a match
split across one output's deltas is found however the outputs interleave,
except that interleaved chat tool calls are blocked under `fail_closed`
(see below).
Each window keeps the last `max_match_len - 1` bytes of its output,
measured both raw and after folding, so a match split across any number of
deltas is found once. A `private_key` hit not closed by its `END` line and
followed only by blanks, line breaks or a split escape may still grow (a
PEM key whose next line has not arrived), so the window holds it from its
start until a scan finds it ended, or the window or the held events pass
`max_scan_bytes` (AGENT-309). A window scans once the text it has not
scanned reaches an eighth of what it holds, so padding that keeps the
window long cannot make scanning quadratic. Up to 31 unfinished outputs
under `fail_open`, or 255 under `fail_closed` (1023 in all), get their own
window; a finished output's window drops its text. Each parallel tool call
takes two outputs, its name and its arguments (AGENT-273). Under
`fail_closed` the text all windows hold is already limited to
`max_scan_bytes`, and a window gives back memory when it trims, so the
higher limit adds little; each unfinished output keeps up to the longest
match's length of text, so many long outputs reach `max_scan_bytes`
before there are 255. Held events go out in order, so under `fail_closed`
a chat tool call is finished when a later-numbered call in its choice
starts (AGENT-273): a chat stream sends its calls one after another, and
only the call in progress then needs to fit in `max_scan_bytes` as raw
SSE. An upstream that interleaves calls writes to a finished output, so
under `fail_closed` its stream is blocked; that needs held events, so
`pass` and `flag` are unaffected. Under `fail_closed` the same holds for
one that starts a call below a higher-numbered call of its choice, or
with a negative index: that call gets a fresh window, while a client
merging calls by position would join it to the call before (AGENT-317).
A choice or tool call sent without an `index` among ones sent with it is
blocked for the same reason, and so is one past the first of its chunk's
array in a stream that sends no index, since a client may merge
index-less entries into one. Under `fail_open` the calls stay open until
`finish_reason`, and held events past `max_scan_bytes` go early.
Past that, or when non-empty text arrives for an output the protocol
already said was finished, a match could be missed: under `fail_closed`
the stream is blocked, under `fail_open` the outputs share one window (or
the finished one reopens) and an `inspection_hold_overflow` row is
written. An `index` is read as clients read it: an integer, a whole-number
float or a numeric string.

How the stream is forwarded depends on `on_hit`:

- **`pass` or `flag`**: each event is forwarded the moment it is
  complete. Hits are only audited.
- **`redact` or `block`**: an event is held until no later match can
  reach back into its text, or until the protocol says its output is
  finished (a chat `finish_reason`, Anthropic `content_block_stop` or
  `message_stop`, a Responses `.done` event, `[DONE]`). A redact
  rewrites the held events' text (the marker where the match starts, the
  rest of the match removed) before any of it is sent. A block drops
  what is held, sends one error event shaped for the stream's protocol
  (OpenAI or Anthropic, with code `inspection_blocked`) and ends the
  stream. If the agent disconnects, the upstream is closed at once, and
text not yet scanned is still judged for the audit.

An event longer than `max_scan_bytes`, one whose strings and their JSON
locations together pass it (long keys repeated over many values), held
text or events past it (counting the copies of the fields a held event
keeps: those later text can reach, and those to rewrite), or lane paths
past it, can't be judged within bounds. Under `fail_closed` the stream is
blocked. Under `fail_open`, held text or events past the bound are
released early and an `inspection_hold_overflow` row is written; an
oversized event and the rest of the stream pass through unscanned, audited
`inspection_skipped` with reason `oversize`. The text held when the
oversized event arrives is judged first, so its hits are redacted or block
before it is released (AGENT-273). An unterminated final event is scanned
when the upstream closes. A content-encoded stream follows `on_error`, as
a buffered body does. When the route also has response
`redaction_patterns`, the inspected stream is buffered whole and the
patterns run on it, as for any response with redaction patterns.

Cost, measured in a release build on macOS ARM64 with the built-in
scanners over 2000 one-word chat deltas (while other builds ran): about
4 to 12 µs of scanning per event. Under `flag` each event is forwarded
as soon as it is scanned. Under `redact` each event waits until the
overlap behind it has arrived. With the built-in scanners the overlap is
about 8 KB of text, set by the longest PEM block `dlp` matches, so the
first byte reached the agent after event 1150. In a live stream that
delay is the time the upstream takes to send another 8 KB, not scanning
time. Routes that need the lowest time to first token should use
`flag`. Re-run:
`cargo test --release --lib measure_stream -- --ignored --nocapture`.

## Audit

One `security`-class row per inspection that found, skipped or failed
something:

| Event | When |
|---|---|
| `inspection_hit` | At least one hit. `decision` is `denied` for a block. |
| `inspection_skipped` | Not scanned: `reason` is `oversize`, `not_text`, `encoded` or `streaming`. |
| `inspection_error` | A scanner failed and nothing was found. |
| `inspection_hold_overflow` | A streamed response's held text or events passed `max_scan_bytes` under `fail_open`, so some text was released before it could be judged. |

Details carry `direction`, `verdict`, `count` and `hits`, each hit as
`{scanner, rule, sha256}` where `sha256` is the hash of the matched span.
At most 64 distinct hits are listed; `count` includes the rest and
`truncated: true` marks the row. A scanner error adds `error`, a skip adds
`reason`, and a redaction that turned into a block (buffered, or a streamed
event no rewrite can reach) adds `redaction_incomplete: true`.
The matched text itself is never recorded.

## Sidecars

ML scanners (PromptGuard 2, CodeShield) run outside the Locksmith
process behind a Unix socket (AGENT-254). Declare each one under
`inspection.sidecars` and name it in a policy as `sidecar:<name>`:

```yaml
inspection:
  sidecars:
    - name: promptguard
      socket: /run/locksmith-inspector/inspector.sock   # absolute path
      timeout_ms: 1000                                  # default 1000
  routes:
    - route: web-search
      response:
        scanners: [injection, "sidecar:promptguard"]
```

Each scan is one `POST /scan` over HTTP/1.1 on its own connection, with
`{"direction", "text"}`, answered by `{"hits": [{"rule", "start", "end",
"score"}]}` in UTF-8 byte offsets. Hits are audited under the scanner id
`sidecar:<name>` like any built-in scanner's. A hit's `rule` is kept to
its first 64 characters, with any character other than an ASCII letter,
digit, `.`, `_`, `:` or `-` written as `_`, since it reaches the audit
row (AGENT-278). A connection failure, a
status other than 200, a malformed answer, a hit outside the text or a
missed `timeout_ms` is a scanner error, and the route's `on_error`
decides. `timeout_ms` bounds each call, connecting and sending the
request included, however slowly the sidecar reads (AGENT-278). A body
makes one or more calls per scanned string, plus calls for the raw body
and, after a redaction, for the rescan of the redacted body, and all of
them share the scan's 5 second
deadline: once it has passed, no further call is made (AGENT-276).

Text sent to a sidecar may hold secrets, so Locksmith checks the uid of
the process serving the socket (`SO_PEERCRED` on Linux, `getpeereid`
elsewhere) and refuses any uid but its own (AGENT-150). A policy whose
only scanners are `injection` or sidecars defaults to `flag`. Sidecars do
not run on streamed (SSE) responses, because a classifier scores whole
texts, not a sliding window. A streamed response on a route with a
sidecar is therefore an inspection error and follows `on_error`: under
`fail_closed` it is refused with 502 `inspection_blocked` before any
header is sent, as an unscannable stream is (AGENT-278); under
`fail_open` it streams with the other
scanners, and the stream's audit row (`inspection_error`, or
`inspection_hit` when something was also found) carries the error in
`details.error`. A `sidecar:` scanner naming no declared
sidecar, an empty or invalid name, a relative socket path or a zero
timeout fails config load. A classifier scores whole texts, and a body's
raw view is one of the texts it is sent, so a sidecar hit can't be cut
out of a JSON body: under `on_hit: redact` it blocks, with
`redaction_incomplete: true` (AGENT-278). Use `flag` or `block` with
sidecars.

`dist/inspector/` holds a reference sidecar built on LlamaFirewall, with
its systemd unit and smoke test. The model weights are not shipped; see
its README for the licence the operator accepts.
