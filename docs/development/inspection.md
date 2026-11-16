# Content inspection

Locksmith terminates every agent request and makes the upstream call
itself, so it sees plaintext in both directions without TLS
interception. The inspection pipeline (`src/inspection/`) uses that
position to scan brokered traffic: requests (body, decoded path and
query) before anything leaves, and responses before anything reaches the
agent. Request headers other than the stripped credential headers are
not inspected. This implements the D-18
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
| `on_error` | `fail_closed` | `fail_open` |
| `max_scan_bytes` | 1 MiB | 1 MiB |

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
| `private_key` | A PEM private key: from the `-----BEGIN ... PRIVATE KEY-----` line through the `END` line (or, with no `END` within 8 KiB, through the base64 and `Proc-Type`/`DEK-Info` lines that follow), so `redact` removes the key, not just its header |
| `jwt` | Three base64url segments whose header decodes to JSON with `alg` |
| `bearer` | The token after `Bearer`: 40+ characters, at least 3 bits/char |
| `base64:<rule>` | A 24 to 4096 character standard-base64 run whose decoded text (UTF-8, one level) matches a rule above; the span is the whole run |
| `entropy` | A 32 to 128 character token run at 4.5 bits/char or more that no other rule covers. Flag-only |

Each rule has a fixed maximum match length; the scanner's
`max_match_len` is the largest (`private_key`, 8,239 bytes). Longer runs
are not matched, so a 50 KiB inline image is neither decoded nor flagged.

### `injection` rules

AGENT-264. Text is folded first: invisible format characters (zero-width
and joiners, soft hyphen, bidi controls, invisible operators, fillers,
variation selectors, TAG characters) are dropped, Cyrillic and Greek
look-alikes and fullwidth ASCII fold to ASCII, each whitespace run
becomes one space, and case is lowered. Hits are reported at their
original byte offsets, so `redact` removes what was really sent.

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
  scanned string by string, object keys included, after JSON unescaping,
  and a redaction rewrites only that string or key. Keys that redact to
  the same marker are numbered (`[REDACTED:dlp]#2`) so no value is lost.
- **Other UTF-8 bodies** are scanned as one text.
- **The raw bytes** of every body are scanned too, read as lossy UTF-8
  with JSON escapes resolved (and percent-decoded for
  `application/x-www-form-urlencoded`). This catches what parsing hides:
  a body that is not valid UTF-8, JSON that fails to parse (trailing
  bytes, deep nesting) with escapes inside, the earlier value of a
  duplicate key, and form encoding. A hit found only this way can't be
  rewritten in place, so `redact` becomes `block` for it.
- **The decoded path and query** of a request are judged the same way,
  never rewritten.
- **Binary bodies** (not UTF-8) are scanned only through the raw view. With
  no hit they pass and are audited `inspection_skipped` with reason
  `not_text`, so uploads are not blocked by a text scanner.
- **Content-encoded bodies** (any `Content-Encoding` other than
  `identity`, such as gzip) can't be scanned as sent and could hide text,
  so they are audited `inspection_skipped` with reason `encoded` and
  follow `on_error`. On a route with a response policy, Locksmith drops
  the agent's `Accept-Encoding` so the upstream answers uncompressed.
- **Bodies over `max_scan_bytes`** are audited `inspection_skipped` with
  reason `oversize` and follow `on_error`: forwarded under `fail_open`,
  blocked under `fail_closed`. A large response is read only up to the
  limit; under `fail_open` the rest is forwarded unscanned, and the
  route's response controls (size cap, redaction) still apply to it.
- **Streamed responses** (`text/event-stream`, and newline-delimited
  JSON: `application/x-ndjson`, `application/jsonl`,
  `application/x-jsonlines`, `application/stream+json`) are not buffered.
  They are audited `inspection_skipped` with reason `streaming` until
  streamed scanning lands (AGENT-265).

Scanning runs on a blocking thread with a 5 second deadline; a scan that
misses it is an `inspection_error` (`scan timed out`) and follows
`on_error`.

A request is scanned as the agent sent it, before Locksmith adds the
route's credential or any profile fixup, so Locksmith's own key is never
a match.

## Audit

One `security`-class row per inspection that found, skipped or failed
something:

| Event | When |
|---|---|
| `inspection_hit` | At least one hit. `decision` is `denied` for a block. |
| `inspection_skipped` | Not scanned: `reason` is `oversize`, `not_text`, `encoded` or `streaming`. |
| `inspection_error` | A scanner failed and nothing was found. |

Details carry `direction`, `verdict`, `count` and `hits`, each hit as
`{scanner, rule, sha256}` where `sha256` is the hash of the matched span.
The matched text itself is never recorded.

## Sidecars

Reserved for ML scanners (PromptGuard 2, CodeShield) that run outside the
Locksmith process over a Unix socket; see AGENT-254.
