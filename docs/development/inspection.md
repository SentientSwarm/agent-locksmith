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
  The path is judged at each decoding a hop may apply. When one of those
  decodings contains a `?` (from `%253F`, say), what follows it is also
  read as a form query, `+` as a space, as a hop that re-parses the
  decoded path would read it (AGENT-315).
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

A string complete in its own event (a snapshot) is scanned alone and never
waits for later text: every Responses event except a `*.delta`
(`response.created`, `.added`, `.done`, `response.completed` and the rest),
Anthropic `message_start`, `message_delta` and `message_stop`, an MCP message
in a JSON-RPC stream (MCP over SSE: a JSON-RPC 2.0 message with only the
spec's members whose `result` holds `tools`, `resources`, `resourceTemplates`,
`prompts`, `tasks`, `contents`, `content`, `structuredContent` or `messages`,
whole only under that member, or whose `method` is `sampling/createMessage` or
`elicitation/create`, whole only in its `params`; MCP notifications, such as
progress and log messages, keep their windows; other JSON-RPC, such as A2A
artifact or ACP session chunks, which clients join, keeps its windows), a chat
chunk's fields outside a choice's `delta` (`logprobs`, Azure content filter
results, `usage`; Azure "On Your Data" text in a choice's `messages[].delta`
gets a window like `delta`), and, within a choice, anything named as protocol metadata
(`type`, `id`, `object`, `model`, `role`, `finish_reason`, `stop_reason`,
`system_fingerprint`, `status`, `item_id`, `call_id`, `response_id`,
`obfuscation`, `service_tier`, `instructions`), such as a delta's `role` or a
tool call's `id`. In a Gemini chunk (any event with a `candidates` array,
whatever `choices`, `type` or event name it also carries) the same holds for
its `modelVersion`, `responseId` and `usageMetadata`, each candidate's
`content.role` and `finishReason`, and a part's `thoughtSignature`, matched by
place (AGENT-273). Only fields later events extend go to a window: a chat or
completions choice's `delta` and `text`, a Responses `*.delta`, an Anthropic
block's text, thinking and tool input, and the opening text clients start them
from (`content_block_start`, a Responses `.added` part's text or refusal, or a
call's arguments). An event a redaction rewrites loses its `logprobs` (`null`,
or `[]` where it is a list): its tokens, their bytes and alternatives would
spell the text the cut removed. The stream's first JSON event fixes whether it
is JSON-RPC, as its first protocol event fixes its scheme: under `fail_closed`
a later JSON event that is not JSON-RPC (a message or batch with
`jsonrpc: "2.0"`) blocks the stream ("stream event names another protocol"),
and under `fail_open` it keeps its windows and writes an
`inspection_hold_overflow` row.

Each of those goes to the window of the output it belongs to, the way a client
rebuilds the stream: each chat choice and each tool call by its `index` inside
`choices`, each Anthropic content block by its `index`, each Responses content
part by `output_index` and `content_index`, each reasoning summary by
`output_index` and `summary_index`, any other Responses output (a call's
arguments) by `output_index`, and all of a Gemini candidate's text parts, in
order, by the candidate's position in `candidates` (clients read
`candidates[0]` and ignore its `index`), thought parts included, since clients
join the answer's parts and some print thoughts inline (AGENT-321, AGENT-322).
A client that leaves thoughts out would join two pieces of answer around a
thought, so under `fail_closed` with held events a thought part after its
candidate's answer text blocks; Gemini streams its thoughts first. Clients
also disagree on a `candidates` or `parts` that is not an array, a candidate
whose `index` is not its position or that has none past position 0, and a
`thought` that is not a boolean (the JavaScript SDK takes only `true`, Python
reads `"false"` by its words), so under `fail_closed` with held events each of
these blocks too. A stream's protocol is fixed by its first protocol event,
and only the indexes its clients use for that event's type count, so an
upstream cannot split one output across windows by adding or varying others (a
top-level `index` on a chat chunk names nothing, and an empty `choices` on
another protocol's event changes nothing). An event naming another protocol,
or whose event name and `type` differ where either names a protocol event (the
SSE default name `message` names none), could be read two ways; and a snapshot
clients append deltas to (Responses `response.created` output, an
`output_item.added` item's content or summary, Anthropic `message_start`
content) carrying text, which real streams send empty, would split a match
from its deltas. Either way, under `fail_closed` the stream is blocked, under
`fail_open` an `inspection_hold_overflow` row is written. So a match split
across one output's deltas is found however the outputs interleave, except
that interleaved chat tool calls are blocked under `fail_closed` (see below).
Each window keeps the last `max_match_len - 1` bytes of its output, measured
both raw and after folding, so a match split across any number of deltas is
found once. A `private_key` hit not closed by its `END` line and followed only
by blanks, line breaks or a split escape may still grow (a PEM key whose next
line has not arrived), so the window holds it from its start until a scan
finds it ended, or the window or the held events pass `max_scan_bytes`
(AGENT-309). A window scans once the text it has not scanned reaches an eighth
of what it holds, so padding that keeps the window long cannot make scanning
quadratic below `max_scan_bytes`. Past it, under `flag` or `pass` a window that
has overflowed may run an eighth over the cap until its next scan and keeps
that rule (AGENT-315). A stream that redacts or blocks scans every push past
the cap, so under `fail_open` a match is found while its events are still
held even once they pass the limit; that costs up to the cap per push in a
full window. Up to 31 unfinished outputs under `fail_open`, or 255 under
`fail_closed` (1023 in all), get their own window; a finished output's window
drops its text, except for its kept tail. That tail carries over when the
output belongs to a join group (AGENT-329): outputs a client joins into one
text. The groups are an Anthropic message's text blocks (`text_delta`) and
Responses content parts. The SDK's `output_text` joins the output text parts;
the group also takes refusal and reasoning text, joining more rather than
less. Tool inputs and arguments, thinking, reasoning summaries, chat choices
and keys an upstream invents never join. Each output keeps its own window,
judged as before. Its start also gets a second window, a bridge, which begins
with the group's kept tail so far, counted as already scanned (after a short
output that is the earlier outputs' tail and then its text, so a match can
cross it too). The bridge scans in batches, as a window does, reports only
matches that cross the join, and is dropped once its scan keeps none of that
tail, or after a last scan when its output finishes. The output's events stay
held while it has a bridge. A new match to redact across the join cannot be
removed whole, since its start went out with the earlier output (and, in
Responses, again in that part's whole-text `.done` copies). The stream is
therefore blocked before the rest goes, with `redaction_incomplete`, as for a
cut no rewrite can make. Under `on_hit: block` it blocks as any match does,
and under `flag` it is flagged. A match the earlier output already reported,
grown into this one, counts once and is cut here too. Clients join a group's
outputs in index order: an output starting below an earlier one of its group
blocks under `fail_closed` ("joined stream outputs out of order"), and under
`fail_open` is not joined and writes an `inspection_hold_overflow` row.
Carried tails and bridges count toward `max_scan_bytes`; past it the tails are
dropped (an `inspection_hold_overflow` row, or a block under `fail_closed`).
A new output of a group starts from the group's open one, which keeps its
window. Text sent to that earlier output afterwards joins nothing a client
joins: under `fail_closed` the stream is blocked ("joined stream outputs
interleaved"), and under `fail_open` an `inspection_hold_overflow` row is
written. Each parallel tool call takes two outputs, its name and its
arguments (AGENT-273). Under `fail_closed` the text all windows hold is
already limited to `max_scan_bytes`, and a window gives back memory when it
trims, so the higher limit adds little; each unfinished output keeps up to the
longest match's length of text, so many long outputs reach `max_scan_bytes`
before there are 255. Held events go out in order, so under `fail_closed` a
chat tool call is finished when a later-numbered call in its choice starts
(AGENT-273): a chat stream sends its calls one after another, and only the
call in progress then needs to fit in `max_scan_bytes` as raw SSE. An upstream
that interleaves calls writes to a finished output, so under `fail_closed` its
stream is blocked; that needs held events, so `pass` and `flag` are
unaffected. Under `fail_closed` the same holds for one that starts a call
below a higher-numbered call of its choice, or with a negative index: that
call gets a fresh window, while a client merging calls by position would join
it to the call before (AGENT-317). A choice or tool call sent without an
`index` among ones sent with it is blocked for the same reason, and so is one
past the first of its chunk's array in a stream that sends no index, since a
client may merge index-less entries into one; servers that send parallel tool
calls in one chunk without an index are blocked. So is an index that is not a
plain JSON integer up to 2^53 (`"1.0"`, `1e0`, `"1"`, `null`): one client
reads it as the number, another as a key of its own. That covers the top-level
indexes the stream's protocol names outputs by and the `index` of an array
element at any depth, such as OpenRouter `reasoning_details` (AGENT-319); a
top-level `index` the protocol does not use is not checked. Under `fail_open`
the calls stay open until `finish_reason`, and held events past
`max_scan_bytes` go early. Past that, or when non-empty text arrives for an
output the protocol already said was finished, a match could be missed: under
`fail_closed` the stream is blocked, under `fail_open` the outputs share one
window (or the finished one reopens) and an `inspection_hold_overflow` row is
written. An `index` is read as clients read it: an integer, a whole-number
float or a numeric string (under `fail_closed` with held events, anything but
a plain integer blocks, as above).

Under `fail_closed`, a write to a finished output gains an upstream nothing
over ending the stream there (AGENT-316). The close judges the output's tail
exactly as the end of the stream would and then releases it. The later write
is blocked, so the client gets the truncated stream plus the block event. A
key prefix shorter than any rule's match goes out either way, as it would from
a buffered scan of the truncated text. Splitting a secret on purpose is the
same evasion an upstream can do by encoding it; inspection does not claim to
stop an upstream built to leak.

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
released early and an `inspection_hold_overflow` row is written. A match
to redact found later that starts in text already released this way, or
grows over it past what an earlier hit covered, can't be removed whole:
the stream is blocked with `redaction_incomplete` (AGENT-330). Whitespace
at the end of released text doesn't count, escaped whitespace (`\n` in
tool arguments) included, so a key whose newlines went early with its cut
lines, or in events of their own, is still redacted. Nor does text a cut
already removed: a token one rule cut before it went early isn't late
for another rule that matches it later (`anthropic_key`, then `bearer`).
An
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

Memory and cost bounds, per stream (AGENT-273):

- **Windows.** Under `fail_open` at most 31 unfinished outputs have a
  window of their own, plus one shared by any more and by finished
  outputs written to again past that limit. Each joined output (an
  Anthropic text block, a Responses content part) still open can also
  hold a bridge window across its join, and each join group carries one
  tail, so the total is about 64 windows' worth. Each window holds up to
  `max_scan_bytes` (an eighth more under `flag` or `pass` once it has
  overflowed). A window fills that far only while its text can't be
  trimmed: padding that folds to nothing, or a PEM key still arriving.
  Under `fail_closed` windows, bridges and carried tails together hold
  at most `max_scan_bytes`, held events have a budget of their own of
  the same size, and the SSE parser buffers up to `max_scan_bytes` of an
  unfinished event. Size `max_scan_bytes` with these multiples in mind.
- **CPU.** Stream scans run on the async worker that forwards the
  stream, not on a blocking thread, and have no deadline; buffered bodies
  are scanned on a blocking thread under a 5 s deadline. Streams use only
  the built-in scanners (sidecars don't scan streams). An event's scan is
  linear in the text it adds, except that past the cap under `redact` or
  `block` each event rescans the full windows it touches.
- **A repeated JSON key in a stream event** hides all but one copy from
  the per-field windows. Under `fail_closed` the stream is blocked. Under
  `fail_open` every copy is still scanned, but only within its own event,
  and an `inspection_hold_overflow` row is written.

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
`reason`, and a redaction that turned into a block (buffered, a streamed
event no rewrite can reach, or a streamed match whose start went early)
adds `redaction_incomplete: true`.
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
