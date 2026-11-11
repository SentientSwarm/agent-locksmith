# Brokered routes (draft)

Status: draft for review. No code yet. Nothing here changes D1 (explicit
account selection) or D4 (authoritative admission) unless a section says so.

## Problem

Many operators already run an **account broker**: a local service that holds
several subscription logins for one provider, refreshes them, and picks an
account per request. Examples are codex-multi-auth for ChatGPT-plan Codex and
teamclaude for Claude plans. A broker gives rotation, quota reserves and
failover that Locksmith deliberately does not.

When both a broker and Locksmith hold the same account, the account breaks.
Most providers rotate refresh tokens: each refresh returns a new refresh
token and invalidates the old one. Two independent refreshers working from one
copied grant invalidate each other. The losing copy then needs a new sign-in,
which looks like an account that "keeps dying".

Pointing a Locksmith route at a broker works today as plain configuration. It
has four problems:

1. **Re-pointing is destructive.** Changing a registration's `upstream` or
   `egress` fires the `registration_destination_changed_authority` trigger
   (migration 0009). It deletes every agent's binding for the route and
   removes the route from every reviewed allowlist. That is correct for an
   unknown destination change, but it makes "move this route onto the broker"
   a re-grant of every agent.
2. **Provider behaviour is keyed on the upstream URL.** Codex header injection
   and body fix-ups trigger when the upstream contains `/backend-api/codex`
   (`is_chatgpt_codex_upstream`). A broker URL does not match, so behaviour
   silently changes with the address.
3. **Attribution stops at the broker.** Locksmith's audit records the agent,
   but not which account served the request, and the broker cannot tell the
   agents behind Locksmith apart.
4. **Nothing prevents the collision.** Nothing stops an operator from also
   bootstrapping a Locksmith OAuth session for an account the broker holds.

## Goals

- Keep one holder and one refresher per upstream grant, enforced where
  Locksmith can enforce it and documented where it cannot.
- Move a route between a direct upstream and a broker without re-granting
  every agent, while keeping the review guarantee migration 0009 provides.
- Keep per-agent identity, allowlists and audit on brokered traffic, and add
  the serving account to the audit.
- Make provider behaviour a declared property of the route, not a substring of
  its URL.
- Let operators cap what each agent can draw from a shared plan.

## Non-goals

- Whether a given provider's terms allow a plan account to serve sandboxed
  agents. That is an owner and policy decision per provider. This design
  provides the mechanism and makes no claim about permission.
- A native multi-account pool inside Locksmith (see Alternatives).
- WebSocket or MITM proxying. Brokers already terminate those for their own
  clients; Locksmith brokered routes are plain HTTP and SSE.

## Design

### 1. Route and backend

A **route** is the agent-facing name (`/api/{route}/...`). Admission, grants
and audit attach to it, as they do to a registration today. A **backend** is
where the route sends traffic: an upstream URL, an egress mode, TLS trust, and
the credential source that goes with that destination.

The split moves *credential bindings* to the backend, not to the route. A
credential is meaningful only for its destination. Keeping a GitHub token bound
while the route moves to a different host would forward it somewhere it was
never reviewed for. So:

- **Grants** (an agent may use the route) stay on the route and survive a
  backend switch.
- **Bindings** (which credential this agent sends) belong to a backend. A
  switch to a backend without the agent's binding leaves the agent granted
  but unbound: 403 `account_binding_missing` until a binding exists. That is
  the existing D1 behaviour, never a silent fallback.

Backend switching is an explicit operator action:
`locksmith route switch <route> --backend <name>`. It is audited as a
security event, compares revisions (`If-Match`), and is refused while the
target backend is disabled. Editing a backend's upstream in place keeps
today's 0009 semantics for that backend: its bindings are cleared. Swapping
between declared backends is the safe path; mutating one is the reviewed path.

Each route has exactly one **active** backend. Multiple backends per route
exist only for switching and, later, the optional fallback (section 6).

Migration: every registration becomes a route with one `upstream` backend of
the same name. Existing bindings move to that backend and existing grants stay
on the route. No behaviour changes until an operator adds a second backend.

### 2. Backend kinds

| Kind | Meaning |
|---|---|
| `upstream` | Today's behaviour: Locksmith injects the selected per-agent credential. |
| `broker` | An external account pool. Locksmith authenticates to the broker with one backend-level key. The broker holds, refreshes and picks the provider account. |

A third kind, a native pool, is deliberately left out (see Alternatives). If
it is ever added, it would be an explicit, opt-in exception to D1.

### 3. Request profiles

A route declares a **profile** that replaces URL-substring heuristics:

| Profile | Behaviour |
|---|---|
| `generic` (default) | Today's generic proxy. |
| `openai-codex-responses` | Codex body fix-ups (G3/G5), required headers (G4), and account-id injection (G2) when the backend is `upstream` with a Locksmith OAuth session. Request timeout 600 s, body limit from the route. |
| `anthropic-messages` | Long-stream timeouts. `anthropic-version` and `anthropic-beta` pass through untouched; only auth headers are replaced. |

Header injection that needs an account (G2) is skipped on `broker` backends,
because the broker sets account headers itself. Body fix-ups stay
profile-controlled on both kinds, since agents send the same bodies either
way. A broker that already applies them makes the fix-ups idempotent no-ops.

During migration, existing routes whose upstream matches the old heuristic get
`openai-codex-responses` automatically, so behaviour does not change.

### 4. Broker contract

A `broker` backend declares:

- **Broker key.** One sealed credential (`stored_bearer` or `stored_header`)
  on the backend itself, not per agent. Locksmith strips the agent's auth
  headers and injects the broker key. Rotating the key is one operator write.
- **Agent identity header** (optional, recommended). Locksmith sets a
  configured header (default `X-Locksmith-Agent: <agent public_id>`) and always
  strips any agent-supplied copy. The broker can attribute and limit per
  agent, and trusts the header only because the request carries the broker
  key.
- **Attribution header capture** (optional). A configured response header
  (for example the broker's account label) is copied into the audit row as
  `details.broker_account`. The capture accepts only a short printable value
  (capped length, no whitespace). It is for labels, never credentials, and is
  hashed instead if the operator marks it sensitive.
- **Health.** A configured probe path and expected status. Probe results
  appear per backend in `/readyz` details and the operational log. A down
  broker does **not** fail daemon readiness, because other routes still serve.
  Its route answers 503 `backend_unavailable` without dispatch.

### 5. Account ownership

The collision is about a **grant**, not an account. Two independent sign-ins
to the same account are separate grants and can coexist. The failure comes
from one grant held twice, which in practice means a refresh token copied
from another tool into Locksmith (`oauth bootstrap --refresh-token-stdin`).

So the primary fix is procedural and enforceable in Locksmith:

- **Fresh grants only for rotating providers.** For profiles whose provider
  rotates refresh tokens, Locksmith accepts sessions only through its own
  sign-in flows (device login, PKCE consent). Refresh-token import is refused
  unless the operator passes an explicit `--adopt-exclusive` acknowledgement.
  That acknowledgement records that the source tool has been signed out.

An **ownership registry** adds a second guard. It lets an operator declare an
account as broker-owned. Locksmith can identify an account only after a
sign-in, from the provider's identity claims (for example
`chatgpt_account_id` in the Codex access token, already extracted for G2).
So the registry is enforced at Locksmith's own sign-in and refresh:

- `locksmith account own <provider> <account-id> --holder broker:<backend>`
  declares that a broker owns the account.
- A Locksmith sign-in or refresh that yields an owned account id is refused
  before the session is stored (409 `account_owned_by_broker`). The provider
  grant is then dropped; nothing is persisted.

Locksmith cannot stop a broker from importing an account Locksmith holds; that
side stays procedural. A broker that lists its roster (for example as JSON
from its CLI) can be imported into the registry by an operator script.

### 6. Circuit breaker and fallback (optional, later)

A backend trips after N consecutive connect failures or 5xx responses within
a window and fails fast with 503 for a cool-down. A route may name one
**fallback backend**, used only when the active one is tripped and only for
requests that have not sent a byte upstream (connect failures), so nothing is
replayed. A fallback that changes the serving account is visible in audit
(`details.backend`, `details.fallback=true`). It is opt-in per route, because
it relaxes "never try another account" for that route only.

### 7. Per-agent caps

Per route and agent: requests per window, and optionally tokens per window.
Requests are counted before dispatch. Token counts come from the profile's
usage events (Codex `response.completed`, Anthropic `message_delta`) after the
response, so a cap can overshoot by at most the in-flight requests. Over the
cap returns 429 `agent_quota_exceeded` with `Retry-After`. Counters live in
SQLite and survive restarts. Caps apply to any backend kind but matter most on
brokers, where every agent shares one plan.

## Alternatives considered

- **Configuration only (no feature).** Works today: a separate route per
  broker with the broker key bound by reference, with agents moved route by
  route. Recommended as the interim. It leaves the four problems above
  unsolved.
- **Native pool first.** Locksmith would hold several accounts per route and
  rotate them. That duplicates mature brokers (quota tracking, reserves,
  per-provider limit APIs) and breaks D1's one-account-per-binding guarantee.
  It also makes Locksmith the refresher for every account, so every other tool
  must stop holding them. That is a large surface for a capability brokers
  already provide.
- **Locksmith as sole holder, brokers as clients.** Brokers would send through
  Locksmith with one account per binding. Brokers would lose rotation and
  failover unless Locksmith grew a pool, which leads back to the previous
  alternative.

## Phasing

1. **Profiles.** Add `profile` to registrations and migrate the substring
   heuristic. Small; no behaviour change.
2. **Route and backend split.** Schema migration, `route switch`, and
   bindings on backends. Grants survive switches.
3. **Broker backend.** Broker key, identity header, attribution capture,
   health in `/readyz` details.
4. **Account ownership.** Fresh-grant rule for rotating providers, registry,
   and refusal at sign-in and refresh.
5. **Per-agent caps.**
6. **Circuit breaker and fallback**, only if operators ask for it.

Each phase ships with QA contract entries and smoke cases under `qa/`.

## Open questions

1. Should `route switch` require the agents' grants to be re-reviewed when the
   new backend is a broker (a different trust shape than a direct upstream), or
   is operator intent enough?
2. Default for the agent identity header: the public id (stable, opaque) or the
   agent name (readable, but it leaks naming to the broker)?
3. Is refusing refresh-token import for rotating providers too strict for
   operators migrating from an existing tool? `--adopt-exclusive` is the
   proposed escape hatch.
4. Should caps also exist on `upstream` backends from phase 5, or only on
   brokers at first?
