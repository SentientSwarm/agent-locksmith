
### Codex quirks (HTTP `codex` connection only)

As of v2.4.0, locksmith owns every codex-specific wire piece:

- Authorization, ChatGPT-Account-ID, OpenAI-Beta, originator (when
  missing) — all injected automatically.
- Body fields store / stream / instructions — injected/overridden
  automatically (instructions preserved if you supply your own).

Your minimal codex call:

```
POST /api/codex/responses
Authorization: Bearer $LOCKSMITH_TOKEN
Content-Type: application/json

{"model":"gpt-5.5","input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"hi"}]}]}
```

Streaming-only — codex `/responses` returns SSE. Your client must
handle it (locksmith forces `stream: true` regardless of what you
send). See the "Codex (OpenAI ChatGPT plan auth) — special case"
section above for the full integration boundary.
