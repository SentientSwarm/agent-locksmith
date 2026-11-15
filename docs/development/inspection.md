# Content inspection

Locksmith terminates every agent request and makes the upstream call
itself, so it sees plaintext in both directions without TLS
interception. The inspection pipeline (`src/inspection/`) uses that
position to scan brokered traffic: request bodies before anything leaves,
and responses before anything reaches the agent. This implements the D-18
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
  scanned string by string after JSON unescaping, so escaping cannot hide
  a match, and a redaction rewrites only that string.
- **Other UTF-8 bodies** are scanned as one text.
- **Binary bodies** (not UTF-8) are not scanned. They pass and are audited
  `inspection_skipped` with reason `not_text`, whatever `on_error` says,
  so uploads are never blocked by a text scanner.
- **Bodies over `max_scan_bytes`** are audited `inspection_skipped` with
  reason `oversize` and follow `on_error`: forwarded under `fail_open`,
  blocked under `fail_closed`. A large response is read only up to the
  limit; under `fail_open` the rest streams through unscanned.
- **Streamed responses** (`text/event-stream`) are audited
  `inspection_skipped` with reason `streaming` until streamed scanning
  lands (AGENT-265).

A request is scanned as the agent sent it, before Locksmith adds the
route's credential or any profile fixup, so Locksmith's own key is never
a match.

## Audit

One `security`-class row per inspection that found, skipped or failed
something:

| Event | When |
|---|---|
| `inspection_hit` | At least one hit. `decision` is `denied` for a block. |
| `inspection_skipped` | Not scanned: `reason` is `oversize`, `not_text` or `streaming`. |
| `inspection_error` | A scanner failed and nothing was found. |

Details carry `direction`, `verdict`, `count` and `hits`, each hit as
`{scanner, rule, sha256}` where `sha256` is the hash of the matched span.
The matched text itself is never recorded.

## Sidecars

Reserved for ML scanners (PromptGuard 2, CodeShield) that run outside the
Locksmith process over a Unix socket; see AGENT-254.
