# OAuth flow

How OAuth-flow providers (codex, copilot, anthropic-oauth,
google-gemini-cli, qwen-cli) work end-to-end through locksmith — from
operator bootstrap, through token refresh, to the per-request hot
path. Phase F shipped the substrate; Phase G added per-agent labels;
Phase G2 added codex-specific header injection.

## Why OAuth differs from API-key auth

Static API keys (Anthropic, OpenAI, Tavily, GitHub PAT, ...) are
operator-provided once and live until rotated. OAuth-flow auth needs
five things static keys don't:

1. **An interactive bootstrap.** PKCE redirect or device-code poll
   loop, completed by a human in a browser.
2. **Two tokens, not one.** A long-lived refresh token, plus a
   short-lived access token (typically 1 hour) backed by it.
3. **Refresh-ahead-of-expiry.** Background task must rotate the
   access token before it expires; a refresh failure is an operational
   event.
4. **Encrypted at-rest storage.** Refresh tokens persist across
   daemon restarts; cleartext on disk is unacceptable.
5. **Provider-specific upstream signaling.** Some providers (codex)
   need extra request headers derived from the access-token JWT.

Locksmith owns all five. Agents see plain HTTP — `POST
/api/codex/responses` with their locksmith bearer — and never touch
refresh tokens, expiry timers, or provider-specific JWT claims.

## The shapes

`AuthSpec` has two OAuth variants:

```rust
AuthSpec::OauthPkce {
    client_id: String,
    redirect_uri: String,        // typically http://127.0.0.1:<port>/callback
    scopes: Vec<String>,
    auth_url: String,
    token_url: String,
}

AuthSpec::OauthDeviceCode {
    client_id: String,
    scopes: Vec<String>,
    device_url: String,
    token_url: String,
}
```

Why two variants instead of one with a flow discriminator: the two
flows have materially different first-time-auth mechanics (PKCE needs
a redirect_uri and code-verifier exchange; device-code needs a polling
loop on a user_code), so unifying them under one variant means every
caller checks the flow type before using fields. Two variants keep the
type system honest. ADR-0005 D1.

Catalog assignment (which provider uses which flow) is in the seed
catalog at `seed/catalog.yaml`:

| Provider | Flow | What it backs |
|---|---|---|
| `codex` | device-code | OpenAI ChatGPT Plus / Pro / Teams plan auth (`/backend-api/codex/responses`) |
| `copilot` | device-code | GitHub Copilot |
| `anthropic-oauth` | PKCE | Anthropic Console (alternative to the static API key) |
| `google-gemini-cli` | PKCE | Google Gemini CLI |
| `qwen-cli` | device-code | Qwen CLI |

`client_id`s are public per the OAuth spec and ship in the seed
catalog; only the refresh token (per-installation) is sensitive.

## Storage

Refresh tokens live in the `oauth_sessions` SQLite table, sealed with
AES-GCM:

```sql
CREATE TABLE oauth_sessions (
    name                       TEXT NOT NULL,
    session_label              TEXT NOT NULL DEFAULT 'default',  -- Phase G
    refresh_token_ciphertext   BLOB NOT NULL,
    refresh_token_nonce        BLOB NOT NULL,                    -- 12-byte AES-GCM nonce
    access_token_ciphertext    BLOB,                             -- nullable; populated after first refresh
    access_token_nonce         BLOB,
    access_token_expires_at    INTEGER,                          -- Unix seconds
    scope                      TEXT NOT NULL DEFAULT '',
    degraded                   INTEGER NOT NULL DEFAULT 0,
    account_id                 TEXT,                             -- Phase G2; extracted from JWT
    created_at                 INTEGER NOT NULL,
    updated_at                 INTEGER NOT NULL,
    PRIMARY KEY (name, session_label)
);
```

The sealing key (32 bytes, base64) is supplied via the
`LOCKSMITH_OAUTH_SEALING_KEY` env var at daemon startup. Operators
generate one at install time and store it in their existing
sealed-creds infrastructure (Keychain on macOS, systemd-creds on
Linux). The daemon decrypts the env-supplied key once at startup,
never logs it, and zeroizes it on drop.

If `LOCKSMITH_OAUTH_SEALING_KEY` is not set, the OAuth admin routes
are not mounted and proxy calls to OAuth registrations return 503
`oauth_sealing_key_unset`. ADR-0005 D2.

## Operator workflow: bootstrap

Bootstrap is the one-time, human-in-the-loop step that mints a refresh
token and seals it into `oauth_sessions`. v1.0 ships
"refresh-token-handoff" mode: operator obtains a refresh token via the
provider's own CLI/flow and hands it to locksmith.

### codex (OpenAI ChatGPT subscription)

```bash
# 1. Install OpenAI's codex CLI on a machine with a browser.
npm install -g @openai/codex
codex login                       # opens browser, completes OAuth dance,
                                  # writes ~/.codex/auth.json

# 2. Extract the refresh token from auth.json:
RT=$(jq -r .OPENAI_API_KEY.refresh_token ~/.codex/auth.json)
# (path varies slightly per codex version; the field is always
# "refresh_token" inside an OAuth credentials object.)

# 3. Hand it to locksmith.
docker exec layer8-locksmith /usr/local/bin/locksmith oauth bootstrap codex \
    --refresh-token "$RT"
```

A successful bootstrap exchange:

1. POSTs to OpenAI's token endpoint with `grant_type=refresh_token` —
   this both validates the token and mints a fresh access token.
2. Decodes the access token's JWT payload, extracts
   `https://api.openai.com/auth.chatgpt_account_id` (Phase G2).
3. Seals refresh + access tokens with AES-GCM and writes the
   `oauth_sessions` row.
4. Emits `oauth_bootstrap_complete` audit event.

Subsequent calls to `/api/codex/...` work without further human
interaction. Refresh happens in the background; the agent sees only
the locksmith bearer.

### Other providers

Same shape: get the refresh token via the provider's own CLI/flow,
hand it to locksmith.

```bash
# anthropic-oauth — Claude Code CLI minting flow
locksmith oauth bootstrap anthropic-oauth --refresh-token-stdin < anthropic-rt.txt

# copilot — GitHub Copilot CLI flow
locksmith oauth bootstrap copilot --refresh-token-stdin < copilot-rt.txt

# google-gemini-cli — Gemini CLI flow
locksmith oauth bootstrap google-gemini-cli --refresh-token-stdin < gemini-rt.txt

# qwen-cli — Qwen CLI flow
locksmith oauth bootstrap qwen-cli --refresh-token-stdin < qwen-rt.txt
```

The interactive `locksmith oauth login` (where locksmith itself drives
the PKCE/device-code flow) is **post-v2** — the cross-host case
(operator on laptop, daemon on cloud VM) requires either
SSH-tunnelled UDS access or a richer remote-bootstrap protocol, and
the substrate to drive PKCE/device-code from inside the daemon. ADR-0005
D5.

## Operator workflow: status / revoke

```bash
locksmith oauth status codex
# name: codex
# session_label: default
# present: true
# degraded: false
# scope:
# created_at: 1778197479
# updated_at: 1778197479
# access_token_expires_at: 1779061478
# audit_session_id: b05ad1526f4d238f

locksmith oauth revoke codex      # clears local state; provider-side
                                  # revoke not yet propagated (v1.1)
```

`audit_session_id` is the SHA-256 of `name:created_at`, truncated to
16 hex chars. Stable across access-token refreshes, different per
bootstrap. Use it to correlate `proxy_request` audit rows with the
session that produced their token. ADR-0005 D4.

## Per-agent OAuth (Phase G — session labels)

A single registration can hold N OAuth sessions, one per
`session_label`. Used to give agents distinct upstream identities:

```bash
# Each agent owner runs codex login under their own ChatGPT account
# and produces a distinct refresh token.
locksmith oauth bootstrap codex --label hermes   --refresh-token-stdin < hermes-rt.txt
locksmith oauth bootstrap codex --label openclaw --refresh-token-stdin < openclaw-rt.txt

# Per-agent override pins each agent to their own label.
locksmith agent set-credential hermes-mini-1   codex --oauth-session hermes
locksmith agent set-credential openclaw-mini-1 codex --oauth-session openclaw
```

Each agent's request resolves the right session by `(name,
session_label)`. See [`per-agent-credentials.md`](per-agent-credentials.md)
for the full operator surface.

The default label is `"default"`. Pre-Phase-G deployments that never
use `--label` see no behavioral change.

## The single-grant trap

**One upstream account cannot back two locksmith labels.** Most
identity providers — including OpenAI ChatGPT, GitHub, Google —
enforce a single-active-grant policy per `(user, client_id)`. Logging
in a second time as the same user **invalidates the prior refresh
token**.

So if you bootstrap two labels from the same upstream account, the
**most-recently-bootstrapped one wins** — the other goes degraded
the next time it tries to refresh (~30 minutes later, when the
access token expires).

`locksmith oauth bootstrap` warns at the time of the trap. When you
bootstrap a non-default label and other labels already exist for the
same registration, the response includes a `warnings` field:

```json
{
  "name": "codex",
  "session_label": "hermes",
  "warnings": [
    "Registration `codex` already has session label(s): default. \
     If those sessions point at the same upstream account as label \
     `hermes`, the provider has likely invalidated the prior refresh \
     tokens (single-grant OAuth policy on OpenAI ChatGPT, GitHub, \
     Google, etc.). Per-agent OAuth requires distinct upstream \
     accounts; see concepts/per-agent-credentials.md."
  ]
}
```

The warning is advisory — bootstrap still succeeds. Operators
deliberately running two upstream accounts (one per agent) can
ignore it. Operators who didn't realize the trap exists get a chance
to step back.

## Refresh task

`oauth::refresh::run` is a `tokio` task that scans `oauth_sessions`
on a tick and refreshes each non-degraded session ahead of expiry.
The refresh schedule is:

```
deadline = access_token_expires_at - max(60s, min(300s, lifetime / 4))
```

Five-minute safety margin handles the typical 1-hour token lifetime
without thrash; the lifetime/4 fallback handles short-lifetime
experimental flows (refresh at 11.25 min remaining for a 15-min
token); the 60s floor prevents pathological refresh-thrash on
misconfigured tokens. ADR-0005 D3.

A per-`(name, session_label)` `Mutex<()>` (the `RefreshLockMap`)
prevents the background task from racing with on-demand
proxy-hot-path refresh.

### Refresh failure

If a refresh attempt fails:

1. The session is marked `degraded = 1`.
2. Audit emits `oauth_refresh_failed` with `details.cause`:
   `revoked` / `provider_5xx` / `network_error` / `bad_response`.
3. The background task does **not** retry on its own — operator
   action is required.
4. Subsequent agent calls return:
   ```
   503 Service Unavailable
   {
     "error": {
       "type": "auth_error",
       "code": "oauth_refresh_failed",
       "message": "OAuth session degraded — operator must re-bootstrap"
     }
   }
   ```
5. Operator runs `locksmith oauth bootstrap <name>` again with a fresh
   refresh token; on success, `degraded` clears and both ciphertext
   columns are replaced.

ADR-0005 D6. Auto-retry was rejected because persistent failure
(revoked token, provider deprecation) is operator-visible work, and
silent retry-storms can compound provider-side rate limits.

## Per-request hot path

When an agent calls `/api/codex/responses` (or any OAuth-backed
provider), `proxy::proxy_handler` does this:

1. **Resolve target.** Look up the `codex` registration in the
   in-memory catalog cache; bind to the per-agent override if one
   exists.
2. **Resolve OAuth token.** `resolve_oauth_token` calls
   `OauthSessionRepository::get(name, session_label)`:
   - Session missing → 503 `oauth_session_missing`.
   - Session degraded → 503 `oauth_refresh_failed`.
   - Sealing key unset → 503 `oauth_sealing_key_unset`.
   - Access token expired → inline refresh under the
     `RefreshLockMap` mutex; success returns the fresh token,
     failure marks degraded and returns 503.
   - Otherwise return `ProxyAuth::Oauth { access_token,
     oauth_session_id, account_id, ... }`.
3. **Strip agent-supplied auth headers.** Drop any
   `Authorization` / `x-api-key` / target-defined auth header that
   the agent may have set, even when the registration says
   `auth: none`. Defense against agent override.
4. **Inject upstream credentials.** `Authorization: Bearer
   <access_token>`.
5. **(Phase G2) Inject `ChatGPT-Account-ID` for codex.** When the
   upstream URL contains `/backend-api/codex` (case-insensitive),
   add `ChatGPT-Account-ID: <account_id>` from the session row.
   Skipped silently for sessions without an account_id (non-codex
   OAuth providers don't use this header).
6. **Route via egress.** Direct or through Pipelock per the
   registration's `egress` field.
7. **Apply response controls.** Optional size cap, content-type
   allowlist, regex redaction (audit logs hashes only, never
   cleartext).
8. **Audit.** One `proxy_request` event per call, with
   `details.auth_mode = "oauth_pkce" | "oauth_device_code"`,
   `details.oauth_session_id = <stable-16-hex>`,
   `details.oauth_session_label = <label>`,
   `details.auth_source = "registration_default" | "agent_override"`.

## The codex special case (Phase G2)

OpenAI's ChatGPT plan auth — the `/backend-api/codex/responses`
endpoint that backs codex CLI's Responses API — requires **two**
pieces of identifying information per request:

1. `Authorization: Bearer <access_token>` — proves the JWT bearer.
2. `ChatGPT-Account-ID: <uuid>` — selects which ChatGPT account /
   workspace the request hits (relevant when one user has access to
   personal + Teams + enterprise workspaces).

The `account_id` lives **inside** the access token's JWT payload,
at:

```
payload["https://api.openai.com/auth"]["chatgpt_account_id"]
```

Native codex CLI extracts it from its own `auth.json`. Both
hermes-agent and openclaw can do the same when they hold the JWT
themselves — but when proxied through locksmith they only see the
locksmith bearer (`lk_<public_id>.<secret>`), which is not a JWT.
Locksmith owns the JWT, so locksmith owns the header.

Locksmith does this transparently:

1. **At bootstrap and every refresh** —
   `oauth::jwt::extract_chatgpt_account_id(access_token)` decodes
   the JWT payload (no signature check — the provider verified it
   when minting; we trust data we sealed ourselves) and returns
   the `chatgpt_account_id` claim. The value is stored in
   `oauth_sessions.account_id`.
2. **On the proxy hot path** — when the upstream URL matches
   `/backend-api/codex` (case-insensitive substring) and the
   session has a non-null `account_id`, locksmith adds the header
   before sending the request.

Both steps fail silently for non-JWT tokens (other OAuth providers
whose access tokens aren't JWTs, or whose JWT payload doesn't
include the OpenAI-specific namespace). The header is never added
to non-codex requests, so other OAuth providers are unaffected.

The matcher is intentionally substring rather than hostname-equal
so test fixtures can use `<mock-server>/backend-api/codex` and
exercise the same code path that production uses against
`https://chatgpt.com/backend-api/codex`. Wire-format details and
test scenarios live in `tests/phase_f_oauth_proxy_test.rs` (the
`g2_*` tests).

### Why not let agents inject the header?

Agents proxied through locksmith never see the access-token JWT —
they only see the locksmith bearer (which is not a JWT). They have
no way to derive `account_id` themselves. Pushing the responsibility
to agents would mean either:

- Letting agents request the access token from locksmith (defeats
  the trust boundary — locksmith exists so agents *don't* hold
  upstream credentials), or
- Letting agents pass through their own `ChatGPT-Account-ID`
  header (agents could spoof another ChatGPT account; locksmith
  has no way to validate).

Locksmith holds the JWT, so locksmith holds the header.

### What happens for native codex CLI usage

Same flow, different actor. Native codex CLI sees the JWT
directly (it minted it, owns the refresh token, refreshes it
itself). When you `codex login`, the CLI writes
`~/.codex/auth.json` with both tokens, decodes the JWT to get
`account_id`, and adds the header on every Responses API call.
Locksmith's contribution is replicating that behavior so an agent
proxied through locksmith doesn't need to be a JWT-aware OAuth
client itself.

## Audit fields

Every proxy_request audit row for an OAuth-backed call carries:

| Field | Meaning |
|---|---|
| `auth_method` | `bearer` / `mtls` — how the **agent** authenticated to locksmith. |
| `details.auth_mode` | `oauth_pkce` / `oauth_device_code` — how locksmith authenticated to the **upstream**. |
| `details.oauth_session_id` | Stable 16-hex identifier per `(name, session_label, created_at)`. |
| `details.oauth_session_label` | The label resolved (Phase G). |
| `details.auth_source` | `registration_default` or `agent_override` (Phase G). |

Audit grep recipes:

```bash
# Every OAuth call in the last 24h, grouped by session:
locksmith audit query --since-ms $(($(date +%s) * 1000 - 86400000)) \
                      --format json \
    | jq '.[] | select(.details.auth_mode | startswith("oauth_")) |
                {tool, agent_name, session: .details.oauth_session_id}'

# Sessions by label for codex:
locksmith audit query --tool codex --since-ms ... --format json \
    | jq '.[] | {agent: .agent_name, label: .details.oauth_session_label}'
```

## Trust boundary

| Held by | Lives where | Touches what |
|---|---|---|
| Refresh token | `oauth_sessions.refresh_token_ciphertext` (sealed) | provider's `token_url` (refresh) |
| Access token | `oauth_sessions.access_token_ciphertext` (sealed) | upstream API requests |
| Account ID (codex) | `oauth_sessions.account_id` (cleartext, JWT-derived) | `ChatGPT-Account-ID` header on `/backend-api/codex` |
| Locksmith bearer | Agent host (`~/.hermes/locksmith.token`) | only locksmith |
| Sealing key | `LOCKSMITH_OAUTH_SEALING_KEY` env var | only the daemon process |

Agents never see refresh tokens, access tokens, account IDs, or the
sealing key. Operators with admin UDS access can read sealed
ciphertext from the DB but not the cleartext (sealing key isn't
exposed via the admin surface). Sealing key compromise + DB
compromise together would expose tokens; either one alone is not
sufficient.

## Codex Responses API body fixup (Phase G3)

OpenAI's `/backend-api/codex/responses` endpoint also requires three
specific body fields that generic OpenAI-compatible clients don't
necessarily set. Native codex CLI sets them because it's
codex-aware; agents that send the more general `openai-responses`
shape miss them and get **400** from chatgpt.com.

The three required fields:

| Field | Required value | Why |
|---|---|---|
| `store` | `false` | Codex rejects `true` — server-side storage isn't supported on this endpoint. |
| `stream` | `true` | The endpoint is fundamentally streaming; `false` is rejected. |
| `instructions` | non-empty string | Codex requires a system-prompt analog. |

Phase G2 owns the codex *header*. Phase G3 owns the codex *body
fields*. Same trust-model premise: locksmith encodes upstream-
specific behavior so agents can stay generic.

### How it works

When the request matches **both** predicates:

1. The upstream is codex (`is_chatgpt_codex_upstream` — same
   case-insensitive `/backend-api/codex` substring match as G2).
2. The request path ends with `/responses` (case-insensitive
   suffix). Other codex endpoints — sessions, model info — pass
   through untouched.

…locksmith inspects the JSON body and applies these rules:

- `store` → forced to `false` (overridden if the agent set `true`,
  added if missing). Audit records this as a `fields_overridden`
  or `fields_added` entry.
- `stream` → forced to `true` (same shape).
- `instructions` → **inject if missing**, **preserve if set**.
  Default text: `"You are a helpful assistant."` Agents that supply
  their own instructions get them through unchanged.

Body parsing is tolerant: non-JSON bodies, malformed JSON, JSON
arrays, JSON null all pass through unchanged (codex itself will 400
on malformed bodies — that's the right error for the agent to see).

### Size cap

Locksmith enforces a 1 MiB cap on bodies it inspects for fixup. Over
the cap returns **413 Payload Too Large** with envelope:

```json
{
  "error": {
    "type": "payload_too_large",
    "code": "codex_body_too_large",
    "message": "Codex request body exceeds 1048576 byte cap"
  }
}
```

Codex bodies are tiny in practice (a few KB). The cap is a defense
against pathological streaming bodies blowing memory during the
inspect+rewrite pass.

### Audit

When fixup happened, the `proxy_request` audit row carries
`details.codex_body_fixup`:

```json
"details": {
  "auth_mode": "oauth_device_code",
  "oauth_session_id": "...",
  "codex_body_fixup": {
    "fields_added": ["instructions"],
    "fields_overridden": ["store", "stream"]
  }
}
```

Field is **omitted entirely** when no fixup happened (agent sent a
correctly-formed body). Operators grepping audit don't see noise on
every codex call — only the fixup-triggering calls surface.

### Default instructions text — soft-API note

`"You are a helpful assistant."` is intentionally neutral. If you
need a specific style (terse, formal, role-play, etc.), set
`instructions` in the agent's request — locksmith preserves it.
Don't rely on the default text staying stable across versions; it
may change to a tighter or more explicit phrasing in future
locksmith releases.

### Why locksmith owns this (not the agents)

Same answer as G2's "why locksmith owns the header":

- Agents proxied through locksmith may not know they're talking to
  codex specifically. They see a generic OpenAI-compatible
  `/responses` endpoint and send a generic body shape.
- Pushing codex awareness back to every agent means every agent
  needs codex-specific code paths, defeating the proxy's value.
- Locksmith already knows (it has the registration metadata, it
  routes by upstream URL). Encoding the quirk in one place is
  cheaper than encoding it in N places.

## See also

- [`per-agent-credentials.md`](per-agent-credentials.md) — operator
  surface for `set-credential` / `unset-credential` and the
  `--oauth-session` flag.
- [`trust-boundary.md`](trust-boundary.md) — broader credential
  flow covering all auth shapes.
- [`agent-integration/hermes.md`](../agent-integration/hermes.md)
  and [`agent-integration/openclaw.md`](../agent-integration/openclaw.md) —
  agent-side configuration to consume OAuth-backed providers.
- [`agents-stack/docs/adrs/0005-oauth-credentials.md`](https://github.com/SentientSwarm/agents-stack/blob/main/docs/adrs/0005-oauth-credentials.md)
  — formal design decisions.
- [`agents-stack/docs/spec/v0.2.0.md`](https://github.com/SentientSwarm/agents-stack/blob/main/docs/spec/v0.2.0.md)
  "OAuth credential variant (Phase F)" + "Per-agent credential
  overrides + OAuth session labels (Phase G)" + "ChatGPT-Account-ID
  injection (Phase G2)" — formal stack spec.
