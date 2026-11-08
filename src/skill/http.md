
## HTTP connections: proxy behavior

| Layer | Locksmith handles | You handle |
|---|---|---|
| Auth (locksmith ↔ agent) | Validates your bearer; enforces ACL; emits audit row per request. | Send `Authorization: Bearer lk_…` on every request. |
| Auth (locksmith ↔ upstream) | Strips your `Authorization` / `x-api-key` headers; injects the explicitly selected upstream credential (API key, OAuth access token, etc.). Refresh-ahead-of-expiry for OAuth providers. | Nothing. You never see the upstream credential. |
| Wire framing | Recomputes `Content-Length` based on the body locksmith forwards. Strips `Transfer-Encoding` for the same reason. | Don't rely on your `Content-Length` reaching upstream — set the body, trust locksmith to frame it. |
| Path routing | Strips `/api/<tool>` prefix; forwards the remainder to the configured upstream URL. | Use the service's documented method and path under `/api/<tool>`. |
| Codex `ChatGPT-Account-ID` header | Extracts from JWT at OAuth bootstrap; injects on `/backend-api/codex/*` requests automatically (Phase G2). | Don't send it yourself — locksmith owns this. |
| Codex body fields `store` / `stream` / `instructions` | On `/responses` paths: forces `store: false`, `stream: true`, injects default `instructions` if missing (Phase G3). | Send the rest of the body shape as the upstream expects. Override `instructions` if you want a non-default system prompt — locksmith preserves user-supplied values. |
| Codex required headers `OpenAI-Beta` / `originator` | Forces `OpenAI-Beta: responses=experimental`; injects `originator: <agent-name>` if missing, preserves yours otherwise (Phase G4). | Optionally set your own `originator` if you want a non-default identifier on codex's side; otherwise nothing to do. |

## HTTP operation descriptions

Fetch authenticated `GET /tools` (or `/models`) for machine-readable discovery.
An optional `http_service` object has `version: 1`, `mode: request_response`
and `operations`: method, relative path, query fields, optional JSON request_body,
expected response, errors and example. Build the URL from your Locksmith base
URL + the listing's public `path` + the operation's `path`, then URL-encode
declared query values. Use your own Locksmith bearer; send JSON bodies with
Content-Type: application/json. Interpret response.content_type as application/json
or text/plain. The reference text example is a string, not JSON wire data.
Do not parse Markdown headings for machine operations. Legacy entries without
a descriptor need their public API documentation from the operator.
These are public descriptions, not method/path permissions or executable plugins.
Do not treat example values as credentials or instructions to select an account.
Execution/tool installation belongs to your runtime. Version 1 describes regular
request/response; it declares no SSE/WebSocket/executable mode. Existing HTTP
stream forwarding is unchanged, including the separately documented Codex case.

For HTTP connections only, each service has its own upstream wire shape. Common
patterns:

- **OpenAI-compatible chat/completions** (lmstudio, ollama, openai, openrouter,
  ai-gateway): `POST /api/<tool>/v1/chat/completions` with the standard
  OpenAI request body (`model`, `messages`, `stream`, etc.).
- **Anthropic Messages API** (anthropic, anthropic-oauth): `POST /api/anthropic/v1/messages`
  with the Anthropic body shape (`model`, `messages`, `max_tokens`, `system`).
- **OpenAI Responses API** (codex): `POST /api/codex/responses` — see the
  dedicated codex section below; locksmith handles the upstream-specific
  quirks but you must send specific headers.
- **REST API tools** (tavily, github, duckduckgo, wikipedia): standard REST
  paths under `/api/<tool>/<rest-of-path>`. Method + body shape per the
  upstream's own docs.

The personalized `/skill` (re-fetched with your bearer) lists the tools
eligible under your ACL. These listings show **ACL eligibility**, not selected source health.
Database listings require current runtime activation; JSON also reports
`account_selected` and `credential_readiness: not_checked`. A listed tool may
still return 403 for no selection or 503 for an unavailable selected source.
Config-only legacy listings say `configuration_only`. `/readyz` does not attest
every per-agent source. On `connection_not_active`, ask the operator to inspect
the saved connection and restore runtime activation. A saved admin write may
return `connection_activation_failed`; it is not rolled back. Never retry another
account or widen a grant automatically.

## HTTP Codex (OpenAI ChatGPT plan auth) — special case

OpenAI's `/backend-api/codex/responses` endpoint has stricter
requirements than the generic OpenAI-compat shape. **As of v2.5.2,
locksmith handles all of them transparently** — agents call codex
the same way they'd call any other OpenAI-compatible endpoint.

### What locksmith does

- **`Authorization` header**: injects the OAuth access token
  (refreshed ahead of expiry; you never see the JWT).
- **`ChatGPT-Account-ID` header (Phase G2)**: extracted from the
  access-token JWT at bootstrap, injected on every
  `/backend-api/codex/*` request.
- **`OpenAI-Beta` header (Phase G4)**: forced to
  `responses=experimental` on every codex request. Your supplied
  value (if any) is stripped — codex requires this exact value.
- **`originator` header (Phase G4)**: injected with your agent name
  if you didn't supply one. Preserves yours if you did.
- **Body field `store`**: forced to `false` (codex rejects `true`).
- **Body field `stream`**: forced to `true` (codex rejects `false`).
- **Body field `instructions`**: injected with default
  `"You are a helpful assistant."` if missing. **Preserved verbatim
  if you set it** — supply your own when you want a non-default
  system prompt.

### What you do

- **Send the request body in the OpenAI Responses API shape**:
  ```json
  {
    "model": "gpt-5.5",
    "input": [
      {
        "type": "message",
        "role": "user",
        "content": [
          { "type": "input_text", "text": "your prompt here" }
        ]
      }
    ]
  }
  ```
  (`store`, `stream`, `instructions` will be added/forced by locksmith.)
- **Handle the streaming response** — codex's `/responses` is
  fundamentally streaming (SSE). The `stream: true` is non-negotiable;
  agents that can't handle SSE will see a long response payload they
  can't process incrementally.

That's it. The minimal call is `POST /api/codex/responses` with
`Authorization: Bearer lk_…`, `Content-Type: application/json`, and
the body above. Everything else is locksmith.

### Codex body cap

Locksmith inspects codex `/responses` request bodies for body fixup.
Bodies > 1 MiB return **413 Payload Too Large** with envelope:

```json
{ "error": { "type": "payload_too_large", "code": "codex_body_too_large" } }
```

Codex bodies are tiny in practice (a few KB). The cap is a defense
against pathological streaming-body edge cases.
