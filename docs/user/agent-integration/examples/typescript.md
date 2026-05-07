# TypeScript / Node recipes

Routing TypeScript and Node agents through layer8-proxy. Works with
`fetch`, `axios`, the official Anthropic + OpenAI SDKs, and any
client that accepts a `baseURL` constructor arg or honors
`*_BASE_URL` env vars.

## SDK-level integration

### Anthropic SDK

```typescript
import Anthropic from "@anthropic-ai/sdk";

const client = new Anthropic({
  baseURL: "http://layer8.lan:9200/api/anthropic",
  apiKey: process.env.LOCKSMITH_TOKEN,    // your agent bearer
});

const resp = await client.messages.create({
  model: "claude-haiku-4-5",
  max_tokens: 100,
  messages: [{ role: "user", content: "Say hi" }],
});
console.log(resp.content[0].type === "text" ? resp.content[0].text : "");
```

The SDK sends `Authorization: Bearer <apiKey>`. Locksmith
authenticates that against its agent registry, strips it, and
injects the real Anthropic `x-api-key` from sealed creds before
forwarding upstream.

Streaming:

```typescript
const stream = await client.messages.stream({
  model: "claude-haiku-4-5",
  max_tokens: 200,
  messages: [{ role: "user", content: "count to 10" }],
});

for await (const event of stream) {
  if (event.type === "content_block_delta" && event.delta.type === "text_delta") {
    process.stdout.write(event.delta.text);
  }
}
```

### OpenAI SDK

```typescript
import OpenAI from "openai";

const client = new OpenAI({
  baseURL: "http://layer8.lan:9200/api/openai/v1",
  apiKey: process.env.LOCKSMITH_TOKEN!,
});

const resp = await client.chat.completions.create({
  model: "gpt-4o-mini",
  messages: [{ role: "user", content: "Say hi" }],
});
console.log(resp.choices[0].message.content);
```

The trailing `/v1` is part of the OpenAI URL shape — locksmith's
seed catalog registers `openai` with upstream
`https://api.openai.com`, so `/api/openai/v1/chat/completions`
becomes the full proxied path.

### LM Studio (OpenAI-compatible)

```typescript
import OpenAI from "openai";

const client = new OpenAI({
  baseURL: "http://layer8.lan:9200/api/lmstudio/v1",
  apiKey: process.env.LOCKSMITH_TOKEN!,
});
```

## Raw `fetch` (Node 18+ / browsers)

```typescript
const LOCKSMITH = "http://layer8.lan:9200";
const TOKEN = process.env.LOCKSMITH_TOKEN!;

const resp = await fetch(`${LOCKSMITH}/api/anthropic/v1/messages`, {
  method: "POST",
  headers: {
    Authorization: `Bearer ${TOKEN}`,
    "anthropic-version": "2023-06-01",
    "Content-Type": "application/json",
  },
  body: JSON.stringify({
    model: "claude-haiku-4-5",
    max_tokens: 100,
    messages: [{ role: "user", content: "Say hi" }],
  }),
});

if (!resp.ok) {
  const err = await resp.json();
  throw new Error(`locksmith ${resp.status}: ${JSON.stringify(err)}`);
}

const data = await resp.json();
console.log(data.content[0].text);
```

### Streaming with `fetch`

```typescript
const resp = await fetch(`${LOCKSMITH}/api/anthropic/v1/messages`, {
  method: "POST",
  headers: {
    Authorization: `Bearer ${TOKEN}`,
    "anthropic-version": "2023-06-01",
    "Content-Type": "application/json",
  },
  body: JSON.stringify({
    model: "claude-haiku-4-5",
    max_tokens: 200,
    stream: true,
    messages: [{ role: "user", content: "count to 10" }],
  }),
});

const reader = resp.body!.getReader();
const decoder = new TextDecoder();
let buffer = "";

while (true) {
  const { done, value } = await reader.read();
  if (done) break;
  buffer += decoder.decode(value, { stream: true });
  const lines = buffer.split("\n");
  buffer = lines.pop() ?? "";
  for (const line of lines) {
    if (line.startsWith("data: ")) console.log(line.slice(6));
  }
}
```

### axios

```typescript
import axios from "axios";

const locksmith = axios.create({
  baseURL: "http://layer8.lan:9200",
  headers: { Authorization: `Bearer ${process.env.LOCKSMITH_TOKEN}` },
});

const resp = await locksmith.post("/api/anthropic/v1/messages", {
  model: "claude-haiku-4-5",
  max_tokens: 100,
  messages: [{ role: "user", content: "Say hi" }],
}, {
  headers: { "anthropic-version": "2023-06-01" },
});
console.log(resp.data.content[0].text);
```

## Discovery and introspection

```typescript
const TOKEN = process.env.LOCKSMITH_TOKEN!;
const LOCKSMITH = "http://layer8.lan:9200";

// What models can this agent reach?
const models = await fetch(`${LOCKSMITH}/models`, {
  headers: { Authorization: `Bearer ${TOKEN}` },
}).then(r => r.json());
console.log(models.models.map((m: any) => m.name));

// What tools?
const tools = await fetch(`${LOCKSMITH}/tools`, {
  headers: { Authorization: `Bearer ${TOKEN}` },
}).then(r => r.json());
console.log(tools.tools.map((t: any) => t.name));

// Self-introspect (markdown).
const skill = await fetch(`${LOCKSMITH}/skill`, {
  headers: { Authorization: `Bearer ${TOKEN}` },
}).then(r => r.text());
```

## Error handling

```typescript
async function callLocksmith(path: string, body: unknown) {
  const resp = await fetch(`${LOCKSMITH}${path}`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${TOKEN}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(body),
  });

  if (!resp.ok) {
    const err = await resp.json();
    switch (resp.status) {
      case 401:
        throw new Error("locksmith bearer is invalid; re-register agent");
      case 403:
        if (err.error?.code === "tool_not_allowed") {
          throw new Error("agent's ACL doesn't permit this tool");
        }
        throw new Error(`locksmith forbidden: ${err.error?.message}`);
      case 503:
        if (err.error?.code === "oauth_refresh_failed") {
          throw new Error("OAuth session degraded; operator action required");
        }
        throw new Error(`locksmith unavailable: ${err.error?.message}`);
      default:
        throw new Error(`locksmith ${resp.status}: ${JSON.stringify(err)}`);
    }
  }

  return resp.json();
}
```

## Token loading from a file

```typescript
import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

const TOKEN_FILE = join(homedir(), ".hermes", "locksmith.token");

function loadLocksmithToken(): string {
  return readFileSync(TOKEN_FILE, "utf-8").trim();
}
```

## OpenClaw / Anthropic CLI / hermes compatibility

CLI tools that consume `*_BASE_URL` env vars work without code change:

```bash
export ANTHROPIC_BASE_URL="http://layer8.lan:9200/api/anthropic"
export ANTHROPIC_API_KEY="lk_<your-bearer>"
export OPENAI_BASE_URL="http://layer8.lan:9200/api/openai"
export OPENAI_API_KEY="lk_<your-bearer>"

# Now any tool respecting these conventions routes through locksmith:
claude --model claude-haiku-4-5 "say hi"   # if claude-cli respects ANTHROPIC_BASE_URL
codex run ...                              # likewise
```

## Working in Bun

The Anthropic and OpenAI SDKs work unchanged under Bun. Native
`fetch` works too. If you hit TLS issues with locally-issued mTLS
certs, set `NODE_TLS_REJECT_UNAUTHORIZED=0` for local dev only —
**never in production**.

## See also

- [curl.md](curl.md) — language-neutral wire shape.
- [python.md](python.md) — Python equivalents.
- [hermes.md](../hermes.md), [openclaw.md](../openclaw.md) —
  agent-specific integration recipes.
