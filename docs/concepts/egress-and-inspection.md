# Egress and inspection

Locksmith controls traffic leaving a deployment in two separate ways:

- **Egress enforcement** decides which hosts a route may reach. It is
  enforced *outside* the Locksmith process, by an egress proxy
  (Pipelock) or by the surrounding network.
- **Content inspection** decides what a request or response may carry.
  It runs *inside* Locksmith, on plaintext, because Locksmith terminates
  the agent's request and makes the upstream call itself.

They protect against different failures. Egress enforcement still holds
when Locksmith's own configuration is wrong. Inspection still holds when
an allowed host is the one being abused. Run both where you can.

## Egress modes

Each route is either `egress: proxied` or `egress: direct` (legacy
`cloud: true` means `proxied`). The deployment-wide `egress.mode` decides
what `proxied` means:

```yaml
egress_proxy: "http://127.0.0.1:8888"   # the Pipelock listener
egress:
  mode: pipelock                         # pipelock | external
```

| Mode | How `proxied` routes leave | Who enforces the host allowlist |
|---|---|---|
| `pipelock` | Through `egress_proxy`. HTTPS upstreams tunnel with `CONNECT`; HTTP upstreams are sent to the proxy as absolute-form requests. | Pipelock, but only in its `strict` mode (see below) |
| `external` | Straight to the upstream. | The surrounding infrastructure: a firewall, a Kubernetes NetworkPolicy, a cloud egress gateway |
| none | Not at all. Each request fails with 503 `egress_proxy_unconfigured` and writes an `egress_unenforced` security audit event. | Nobody, so Locksmith refuses |

- If `egress.mode` is absent, it is `pipelock` when `egress_proxy` is
  set, and none otherwise. A proxied route never quietly falls back to a
  direct connection.
- `egress.mode: pipelock` without `egress_proxy` fails config load
  ("egress.mode `pipelock` requires egress_proxy").
- `egress: direct` routes always connect straight to the upstream, in
  every mode. Use them only for LAN and loopback destinations.
- Routes sent without a proxy (`direct`, and `proxied` under
  `external`) ignore `HTTP_PROXY`, `HTTPS_PROXY` and `ALL_PROXY` in the
  daemon's environment, so they never reach a proxy that no route names.
- An OAuth route's token calls (bootstrap, device login and refresh)
  take the route's egress: a `proxied` route's token endpoint goes
  through `egress_proxy` under `pipelock`, directly under `external`,
  and nowhere when neither is configured (the call fails with
  `egress_proxy_unconfigured` and the session is left as it was). The
  egress policy lists those token hosts with the route. Keep them on the
  proxy's allowlist: a token call the proxy refuses leaves the session
  `reconnect_required`, which needs a local revoke and then a fresh
  bootstrap or device login.
- Native MCP OAuth token calls (whose connections are always `direct`)
  and CRL fetches connect directly in every mode and ignore those
  variables too, so allow those hosts in your network's egress rules.
- `external` is a statement that something else enforces egress.
  Locksmith cannot check that claim. Choose it only where that control
  exists and allows no more than your proxied routes need.

### Pipelock must run in `strict` mode to enforce an allowlist

Pipelock's `balanced` mode is its default. In `balanced` mode every host
is reachable unless it is on Pipelock's blocklist, and `api_allowlist`
only exempts hosts from that blocklist. Only `mode: strict` turns `api_allowlist` into the list of
hosts that may be reached. Without `strict`, `pipelock` mode still gives
you Pipelock's blocklist, its checks on what it can see (for HTTPS
without TLS interception, only the host name) and its own egress record,
but it does not limit where a proxied route can go.

### Keep Pipelock's allowlist in step with the routes

```bash
locksmith egress policy --format json   # effective mode, hosts, and routes per host
locksmith egress policy --pipelock      # a Pipelock api_allowlist fragment
```

The policy lists every host reached by an enabled `proxied` route, so
generate Pipelock's allowlist from it rather than maintaining two lists.
It is the destination gate only under `mode: strict`.
Re-run it after adding, re-pointing or disabling a route. The proxy URL
is never returned. See [CLI reference: egress policy](../reference/cli-reference.md#egress-policy).

### What you lose without Pipelock

With `external`, or with routes marked `direct`:

- No allowlist enforced outside Locksmith, unless your network supplies
  one (the same holds for Pipelock outside `strict` mode). A route
  edited to point at a new host reaches it immediately.
- No egress record independent of Locksmith's own audit log.
- `locksmith egress policy --pipelock` is still useful as the list of
  hosts that your own controls should allow.

Content inspection, the route ACL, credential selection and the audit
log are the same in every mode.

## Brokered routes

A [broker route](../reference/cli-reference.md#broker-routes) sends requests to a
broker that holds the provider accounts and makes the provider call
itself. Locksmith's inspection policy for the route runs before the
request is handed to the broker, and on the response the broker returns.
The rest is outside Locksmith (AGENT-267):

- The broker's own connections to providers do not pass through
  Locksmith, so they are not in Locksmith's egress policy and not seen by
  Pipelock. A broker is usually reached as an `egress: direct` loopback
  or LAN route. Pipelock then sees nothing for it, and the egress policy
  does not list it.
- Constrain the broker's egress where it runs, with its own proxy setting
  or a network policy, and allow only its providers.
- If you mark the broker route `proxied`, Pipelock sees only the hop from
  Locksmith to the broker.

## TLS interception and per-route CAs

Locksmith does not need TLS interception to inspect traffic, because it
already holds the plaintext. If you turn interception on in the egress
proxy, it re-signs each upstream certificate with the proxy's own CA.
That has two consequences:

- **Per-route CAs break.** A route set with `--upstream-ca-file` trusts
  only that CA, so the proxy's re-signed certificate fails verification
  and every request fails. This is by design: the route CA pins who may
  answer. Leave such routes un-intercepted at the proxy, or mark them
  `direct` if they are on your network.
- **Other routes need the proxy's CA.** Add it with the
  `tls.upstream_ca_bundle` config key. That key only adds roots;
  Locksmith has no setting that turns verification off.

Interception also lets the proxy read the credential that Locksmith
injects, and the refresh tokens and authorization codes that a proxied
OAuth route's token calls carry. Plain-HTTP upstreams already expose it to the proxy, because
they are sent to the proxy unencrypted.

## Content inspection

Policy is set per route and per direction under `inspection.routes` in
the config file, which needs a restart to change. Each policy names its
scanners and what a hit does (`pass`, `flag`, `redact` or `block`). It
also says what happens when a body can't be scanned (`fail_open` or
`fail_closed`). Requests fail closed by default; responses fail open,
unless the policy redacts or blocks. A request is scanned as the agent sent it, before
Locksmith adds the route's credential. Every hit, skip and error writes a
`security` audit row, and the audit never stores the matched text.

The built-in scanners are `dlp` (credential formats), `injection`
(prompt-injection phrasing) and `literal:<text>` (exact strings such as
canary tokens). ML classifiers run in a sidecar named as
`sidecar:<name>`. The full rule lists, the scanned body forms and the
streaming behavior are in
[content inspection](../development/inspection.md).

## The classifier gap

The built-in `injection` scanner is a phrase list (AGENT-257). Until a
classifier sidecar is deployed, treat it as a tripwire, not a defense.

**It catches** known phrasing, such as:

- "ignore previous instructions", "disregard the above"
- role reassignment ("you are now DAN") and "from now on"
- fake system labels and chat-template tokens (`<|im_start|>`, `[INST]`,
  `<<SYS>>`)
- "reveal your system prompt" and "no restrictions"
- explicit exfiltration and concealment ("send the credentials to", "don't
  tell the user")
- runs of invisible characters and Unicode TAG characters

It matches after folding the text: invisible characters and accents are
dropped, look-alike letters become ASCII (Cyrillic, Greek, fullwidth,
mathematical, small capital, circled, superscript, Roman numerals),
whitespace collapses and case is lowered. The common spacing, accent and
look-alike tricks don't evade it, though a letter outside those tables
still can.

**It misses**:

- Paraphrase and novel wording. Anything not on the list passes.
- Other languages. Folding maps look-alike letters, but the phrases are
  English.
- Encoded text. The scanner doesn't decode base64, URL encoding or other
  encodings (only `dlp` decodes base64), and it can't read images.
- Indirect instructions that read as ordinary content, such as a page
  asking the reader to fetch a URL or run a command.
- Attacks spread across several separate fields or messages, each of
  which looks harmless.

A policy whose scanners are only `injection` or sidecars defaults to
`on_hit: flag`. Set `block` or `redact` deliberately, knowing the false
positives a phrase list brings on pages that discuss prompt injection.

### Closing it with a sidecar

`dist/inspector/` is a reference sidecar built on LlamaFirewall
(PromptGuard 2). Declare it under `inspection.sidecars` and add
`sidecar:<name>` to a route's scanners (AGENT-254). Two limits remain:

- **Sidecars don't scan streamed (SSE) responses**, because a classifier
  scores whole texts. On a route with a sidecar, a streamed response is
  an inspection error. Under `fail_closed` (the default when the policy
  redacts or blocks) it is blocked. Under
  `fail_open` it streams with only the built-in scanners, so for
  prompt injection the phrase list is all that applies.
- **The model weights are not shipped.** The operator accepts their
  licence when installing them; see `dist/inspector/README.md`.

## Related

- [Trust boundary](trust-boundary.md): who holds which credential.
- [Architecture](architecture.md): where egress and inspection sit in
  the request path.
