# `/skill` reference

`GET /skill` is locksmith's auth-optional rendering surface — it
returns a markdown blob the calling agent can use to bootstrap its
tool catalog. Two rendering modes:

| Auth | Behavior | Cache |
|---|---|---|
| No `Authorization` header | Generic form (no tool/model leak) | `public, max-age=86400` |
| Valid agent bearer | Personalized form (this agent's tools, ACL, etc.) | `private, no-cache, no-store` |
| Invalid bearer | 401 (no silent downgrade) | n/a |

The auth-optional shape exists so a fresh agent can fetch a
"what is this proxy?" overview at startup without needing
credentials yet, while authenticated agents get an actionable
catalog. Listings show ACL eligibility, not binding existence or source health.
Both forms explain missing-binding 403 diagnosis before deliberate operator
repair, actual ACL denial, and selected-source 503 diagnosis.

## Wire shape

```http
GET /skill HTTP/1.1
Host: layer8.lan:9200
[Authorization: Bearer lk_...]   ← optional

HTTP/1.1 200 OK
Content-Type: text/markdown; charset=utf-8
Cache-Control: public, max-age=86400          ← when no bearer
Cache-Control: private, no-cache, no-store    ← when bearer

# Locksmith — agent skill
...
```

## Generic (unauthenticated) form

Returned when no `Authorization` header is present. Same content
for every requester — no operational leak (no tool list, no agent
list, no version detail beyond what `/version` provides).

Sample (illustrative; the bundled content evolves with releases):

```markdown
# Locksmith — agent skill

Without a bearer, `/skill` returns generic guidance. With your valid bearer,
it includes a **Personalized for** section containing:

- Your agent name and `public_id`.
- Your ACL-eligible tools (and short descriptions).
- Per-tool integration guidance.
- An audit-debug recipe scoped to your `public_id` for your operator.
```

The protocol examples describe common API shapes; they do not advertise
configured services or promise that an arbitrary service supports chat.
The generic response contains no deployment catalog or agent identity.

The generic form serves as a self-describing landing page. Useful
for human visitors hitting the URL in a browser, or for agents that
do a "what kind of endpoint is this?" probe before settling into a
session.

## Personalized (authenticated) form

Returned when a valid agent bearer is presented. Includes the
agent's specific tool catalog, ACL, audit-debug hints. Sample
(illustrative):

```markdown
## Personalized for `reference-consumer`

You're authenticated as **reference-consumer** (`public_id=<agent-public-id>`).

### Tools eligible under your ACL

| Tool | Description |
|---|---|
| `accounts` | Reference account check |
| `customer-jobs` | Customer job API |

This list shows ACL eligibility, not account binding existence or source health.
A listed tool can still return 403 for missing selection or 503 for an unavailable source.
```

Names/descriptions come from the same catalog listing as authenticated `/tools`.
Database-backed discovery requires current runtime activation; disabled, missing
or pending registrations are omitted. Generic output exposes no deployment catalog; other agents receive only
their own eligible services. A personalized section means the request
was authenticated; it does not ask an already authenticated caller to refetch.

Fetch `/tools` for each service's optional typed `http_service` descriptor.
Use its actual method/path, query/body and response content type; the reference
`GET /check` returns plain text, while the example customer `GET /v2/jobs`
returns JSON. Do not assume a listed service supports `/v1/chat/completions`.
Legacy entries without descriptors need their public API documentation.

JSON discovery also reports `activation`, `account_selected` and
`credential_readiness: not_checked`. An active registration is not proof that
this agent has a selected or usable account. `/readyz` does not attest each
selected source. Config-only legacy listings say `configuration_only`.

For a 403, the personalized document supplies these operator commands with
the caller's actual public ID:

```sh
locksmith audit query --agent <agent-public-id> \
  --since-ms <ms>
locksmith agent credentials list <agent-public-id>
locksmith agent set-credential <agent-public-id> <tool> --auth 'bearer=<ENV_VAR>'
```

Replace `<ms>` with the start of the incident window in Unix milliseconds.
Inspect `details.reason` first: `account_binding_missing` needs a deliberate
selection, whereas `not_in_allowlist`/`in_denylist` need intended policy review.
Widening a grant does not repair a missing binding. The source reference is an
operator-chosen example, never a credential value to send to the agent.

For a selected-source 503, inspect that same safe selection list and audit.
The query includes security and proxy events: 403s use `details.reason`;
503 `credential_unavailable` uses `details.credential_cause`, while
OAuth failures use `details.oauth_cause` and activation failures use
`details.cause`. Do not filter out proxy events
when diagnosing source failures.
Diagnose the selected environment/stored/1Password reference or OAuth label;
repair it or deliberately select an approved account. An unavailable source
must not trigger alternate/default/unauthenticated retries. OAuth bootstrap
repairs custody; a separate explicit nonempty label selection grants its use.
On `connection_not_active`, inspect the saved registration and restore runtime
activation; a failed activation can leave a saved write pending. See
[operator troubleshooting](../operator/account-binding-troubleshooting.md).

The personalized form is what agentskills.io–compatible tools can
ingest at startup to build their tool catalog without static config.

## Shape stability

The endpoint returns `Content-Type: text/markdown; charset=utf-8`.
The content shape (headings, sections) is **not** stable — it
evolves as new features land. Agents that consume `/skill` should
read it as guidance; they should not depend on specific Markdown
structure for machine parsing.

For machine-readable tool catalogs, use `GET /tools` + `GET /models`
(JSON, stable contract). `/skill` is the human / LLM-ingestible
overlay.

Optional typed `http_service` descriptors in JSON discovery provide the
[versioned operation contract](http-services.md). Fetch them with your own bearer
and build calls in your runtime; use the described method, public path, query,
body and response type. Do not derive machine operations from Markdown headings.

## Use cases

### Agent bootstrap discovery

A fresh agent at startup can:

1. `GET /skill` (no auth) → identify Locksmith and read
   the generic info.
2. Look up its bearer (from env / token file).
3. `GET /skill` (with bearer) → grab the personalized catalog.
4. Fetch authenticated `/tools` (or `/models`) for machine-readable
   operations and construct calls in its own runtime. Locksmith installs no tools.

## Cache headers

The `Cache-Control` distinction matters in practice:

| Form | Cache-Control | Why |
|---|---|---|
| Generic | `public, max-age=86400` | Same content for everyone; CDN-cacheable. |
| Personalized | `private, no-cache, no-store` | Per-agent content; ACL changes need to surface immediately. |

When operators modify an agent's ACL, the personalized `/skill` next
fetch reflects the change — no 24-hour cache to wait through.

## Streaming

`/skill` returns a complete Markdown body (no streaming). For large catalogs, consider whether you actually need them all in the agent's
context — `/tools` + `/models` JSON is more efficient for
machine-only consumers.

## Errors

| HTTP | When |
|---|---|
| 200 | Always when content rendered (generic OR personalized). |
| 401 | Bearer present but invalid. |
| 5xx | Daemon problem (rare). |

Note there's no 404 — `/skill` is always served.

## Implementation reference

The handler is `app::skill_handler` in `src/app.rs`. Generic
content lives in `src/skill_template.md`; personalized rendering is
`src/skill.rs::render_authenticated`.

To customize the generic content for a forked deployment: edit
`src/skill_template.md` + rebuild. To customize personalized
rendering: extend `skill::render_authenticated` (it has access to
`AgentIdentity` and the caller's ACL-filtered `(name, description)` list).

## See also

- [wire-contract.md](wire-contract.md) — full wire surface (more
  than just `/skill`).
- [openclaw.md](openclaw.md), [hermes.md](hermes.md) — agent-specific
  recipes.
- [agentskills.io](https://agentskills.io) — the markdown-skill
  format `/skill` is loosely compatible with.
