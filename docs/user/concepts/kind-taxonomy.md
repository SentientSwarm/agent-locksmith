# Kind taxonomy (v2.0.0+)

Status: **v2.0.0+** — this page describes the catalog substrate landing in agent-locksmith v2.0.0 / layer8-proxy v0.1.0 release. Tracking: Linear MVP project, Phase E.

Until v2.0.0 ships, every registration is implicitly `kind=tool` and the `/tools` endpoint returns the homogeneous catalog. This page documents what changes.

## What's changing

Locksmith currently treats every registration as a "tool". From v2.0.0, registrations gain a `kind` discriminator with three values:

- **`model`** — LLM, embedding, reranker, audio, image, or any model-shaped service. Discoverable via `GET /models`. Most have authenticated upstreams; `metadata.modality` distinguishes text/embedding/audio/image.
- **`tool`** — anything that's not a model. Web search, code repos, document fetch, sandboxes. Discoverable via `GET /tools`. May be authless (`auth: none` — see [error-envelope.md](error-envelope.md)).
- **`infra`** — operator-only middleware that the proxy itself calls. Today: `lf-scan`. Future: structured-output validators, additional content scanners. **Not** discoverable by agents — `GET /infra` does not exist.

## Why split

Agents reason differently about models (rate-limit-sensitive, often token-priced, prompt-shaped) vs tools (latency-sensitive, response-shaped, ACL-policy-shaped). Mixing them in a single `/tools` catalog conflates two distinct mental models.

Operators reason differently about infra (always-present middleware) vs agent-callable surface (deliberate ACL grants).

Splitting cleans up:
- **Discovery**: agents fetch only the kind they care about.
- **Naming**: a single global namespace, but `GET /models` and `GET /tools` are independent surfaces.
- **Operator UX**: `locksmith model put`, `locksmith tool put`, `locksmith infra put` — three coherent subcommands instead of one with kind-conditional flags.

## What stays the same

- **ACL is flat**: an agent's allowlist references names directly. The agent doesn't need to know whether `anthropic` is a model or a tool — it just has `anthropic` in its allowlist. Locksmith resolves the kind at request time and applies the same allow/deny check regardless.
- **The wire envelope** ([error-envelope.md](error-envelope.md)) — same shape, with two additional codes (`wrong_kind`, `auth_required`).
- **Trust boundary** ([trust-boundary.md](trust-boundary.md)) — unchanged. The kind a registration has doesn't change who holds what credential.

## Authless tools

Some `kind=tool` entries are deliberately public — DuckDuckGo, Wikipedia, public document APIs. v2.0.0 introduces explicit `auth: none` to distinguish "deliberately public, operator chose authless" from "operator forgot the API key":

```yaml
- name: duckduckgo
  kind: tool
  description: "DuckDuckGo Instant Answer API (authless)"
  upstream: "https://api.duckduckgo.com"
  auth: none
  egress: proxied
  timeouts: { request_seconds: 30, idle_seconds: 30 }
```

`kind=tool` registered without an `auth:` block is rejected at register-time with `400 / auth_required`. Implicit "no auth block means authless" was a footgun we closed.

`kind=model` requires a non-`none` auth (every model upstream we ship to v0.1.0 charges for tokens — authless is a category mistake).

## Built-in seed catalog

v2.0.0 also ships a curated catalog (`/etc/locksmith/seed/catalog.yaml`) baked into the locksmith image. First-boot loads it into the registrations table; the operator only contributes credentials and per-host overrides.

UX before v2.0.0:
> "To use Anthropic, write `tools/anthropic.yaml` describing the upstream URL, auth shape, timeouts, body limits…"

UX from v2.0.0:
> "Anthropic is built in. Provide `ANTHROPIC_API_KEY` in your `.env`. Done."

Operators can disable a built-in (sets `disabled=1`, doesn't delete) and override fields (sets `seed=0`, image upgrades preserve the override). See [Phase E.7](https://linear.app/wemodulate/issue/WEM-271) for the full mechanic.

## Future direction (post-v2.0.0)

`kind=infra` opens the door to a v0.3+ middleware-pipeline reframe: the proxy hot path becomes a programmable sequence of internal handlers, each registered as `kind=infra`. Audit, content scanning, structured-output validation, prompt-injection detection — all become composable middleware.

v2.0.0 ships only the storage + registration surface for `kind=infra`. The actual pipeline composition is post-v2.0.0 design (probably v0.3 spec). This page will be expanded then.

## See also

- [trust-boundary.md](trust-boundary.md)
- [agent-identity-and-acl.md](agent-identity-and-acl.md)
- [error-envelope.md](error-envelope.md)
- `agents-stack/docs/adrs/0004-kind-taxonomy.md` — formal decision (post-Phase E).
- Linear MVP project, Phase E — implementation tickets.
