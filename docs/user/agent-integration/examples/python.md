# Python recipes

Routing Python agents through layer8-proxy. Works for any HTTP
client (`httpx`, `requests`, `aiohttp`) and for the official
provider SDKs that support `base_url`.

## SDK-level integration

The Anthropic and OpenAI SDKs both honor a `base_url` constructor arg
(or `*_BASE_URL` env var). Locksmith works as a drop-in replacement.

### Anthropic SDK

```python
import anthropic
import os

client = anthropic.Anthropic(
    base_url="http://layer8.lan:9200/api/anthropic",
    api_key=os.environ["LOCKSMITH_TOKEN"],     # your agent bearer
)

resp = client.messages.create(
    model="claude-haiku-4-5",
    max_tokens=100,
    messages=[{"role": "user", "content": "Say hi"}],
)
print(resp.content[0].text)
```

The SDK sends `Authorization: Bearer <api_key>`. Locksmith
authenticates the bearer (it's actually your agent token, not an
Anthropic key), strips that header, and injects the real Anthropic
`x-api-key` from sealed creds before forwarding.

Streaming works natively:

```python
with client.messages.stream(
    model="claude-haiku-4-5",
    max_tokens=200,
    messages=[{"role": "user", "content": "count to 10"}],
) as stream:
    for text in stream.text_stream:
        print(text, end="", flush=True)
```

### OpenAI SDK

```python
from openai import OpenAI
import os

client = OpenAI(
    base_url="http://layer8.lan:9200/api/openai/v1",
    api_key=os.environ["LOCKSMITH_TOKEN"],
)

resp = client.chat.completions.create(
    model="gpt-4o-mini",
    messages=[{"role": "user", "content": "Say hi"}],
)
print(resp.choices[0].message.content)
```

Note the trailing `/v1` — OpenAI's SDK appends paths under `base_url`,
and the v1 prefix is part of the OpenAI URL shape. The seed catalog's
`openai` registration upstream is `https://api.openai.com`, so
`/api/openai/v1/chat/completions` is the full proxied path.

### LM Studio (OpenAI-compatible)

LM Studio exposes an OpenAI-compatible API. Use the OpenAI SDK with
locksmith's `lmstudio` registration:

```python
from openai import OpenAI

client = OpenAI(
    base_url="http://layer8.lan:9200/api/lmstudio/v1",
    api_key="locksmith-bearer-here",   # from LOCKSMITH_TOKEN env
)
```

## Raw HTTP client (httpx)

For full control over the wire shape, or for providers without a
dedicated SDK:

```python
import httpx
import os

LOCKSMITH = "http://layer8.lan:9200"
TOKEN = os.environ["LOCKSMITH_TOKEN"]

resp = httpx.post(
    f"{LOCKSMITH}/api/anthropic/v1/messages",
    headers={
        "Authorization": f"Bearer {TOKEN}",
        "anthropic-version": "2023-06-01",
        "Content-Type": "application/json",
    },
    json={
        "model": "claude-haiku-4-5",
        "max_tokens": 100,
        "messages": [{"role": "user", "content": "Say hi"}],
    },
    timeout=600.0,                # cloud LLM calls can take a while
)
resp.raise_for_status()
print(resp.json()["content"][0]["text"])
```

### Streaming with httpx

```python
with httpx.stream(
    "POST",
    f"{LOCKSMITH}/api/anthropic/v1/messages",
    headers={
        "Authorization": f"Bearer {TOKEN}",
        "anthropic-version": "2023-06-01",
        "Content-Type": "application/json",
    },
    json={
        "model": "claude-haiku-4-5",
        "max_tokens": 200,
        "stream": True,
        "messages": [{"role": "user", "content": "count to 10"}],
    },
    timeout=600.0,
) as r:
    for line in r.iter_lines():
        if line.startswith("data: "):
            print(line[6:])
```

### Async (aiohttp)

```python
import aiohttp
import asyncio
import os

async def main():
    async with aiohttp.ClientSession() as session:
        async with session.post(
            "http://layer8.lan:9200/api/anthropic/v1/messages",
            headers={
                "Authorization": f"Bearer {os.environ['LOCKSMITH_TOKEN']}",
                "anthropic-version": "2023-06-01",
            },
            json={
                "model": "claude-haiku-4-5",
                "max_tokens": 100,
                "messages": [{"role": "user", "content": "Say hi"}],
            },
        ) as resp:
            data = await resp.json()
            print(data["content"][0]["text"])

asyncio.run(main())
```

## Discovery and introspection

```python
import httpx, os

TOKEN = os.environ["LOCKSMITH_TOKEN"]
LOCKSMITH = "http://layer8.lan:9200"

# What models can this agent reach?
models = httpx.get(
    f"{LOCKSMITH}/models",
    headers={"Authorization": f"Bearer {TOKEN}"},
).json()["models"]
print([m["name"] for m in models])

# What tools?
tools = httpx.get(
    f"{LOCKSMITH}/tools",
    headers={"Authorization": f"Bearer {TOKEN}"},
).json()["tools"]
print([t["name"] for t in tools])

# Self-introspect (markdown).
skill = httpx.get(
    f"{LOCKSMITH}/skill",
    headers={"Authorization": f"Bearer {TOKEN}"},
).text
```

## Error handling

```python
import httpx

resp = httpx.post(
    f"{LOCKSMITH}/api/anthropic/v1/messages",
    headers={"Authorization": f"Bearer {TOKEN}"},
    json={...},
)

if resp.status_code == 401:
    # Bearer rejected — re-fetch from token store, or fail loudly.
    raise RuntimeError("locksmith bearer is invalid; re-register agent")
elif resp.status_code == 403:
    # ACL denied — operator hasn't granted this tool. Ask the operator.
    err = resp.json()["error"]
    if err.get("code") == "tool_not_allowed":
        raise RuntimeError(f"agent's ACL doesn't permit anthropic")
elif resp.status_code == 503:
    err = resp.json()["error"]
    if err.get("code") == "oauth_refresh_failed":
        # OAuth session degraded — operator must re-bootstrap.
        raise RuntimeError(f"OAuth session degraded; operator action required")
```

## Token loading from a file (hermes-style convention)

```python
from pathlib import Path

TOKEN_FILE = Path.home() / ".hermes" / "locksmith.token"

def load_locksmith_token() -> str:
    """Convention from hermes-site/launch-hermes.sh: token in
    ~/.hermes/locksmith.token, mode 0600, single line."""
    return TOKEN_FILE.read_text().strip()
```

## OpenClaw / hermes / Anthropic CLI compatibility

Most CLI tools that consume `*_BASE_URL` env vars work without
modification:

```bash
# Set once in the shell:
export ANTHROPIC_BASE_URL="http://layer8.lan:9200/api/anthropic"
export ANTHROPIC_API_KEY="lk_<your-bearer>"
export OPENAI_BASE_URL="http://layer8.lan:9200/api/openai"
export OPENAI_API_KEY="lk_<your-bearer>"

# Then any tool that uses these conventions works:
claude --model claude-haiku-4-5 "say hi"   # if claude-cli respects ANTHROPIC_BASE_URL
codex run ...                              # similar
```

## See also

- [curl.md](curl.md) — language-neutral wire shape.
- [typescript.md](typescript.md) — TS / Node equivalents.
- [hermes.md](../hermes.md), [openclaw.md](../openclaw.md) —
  agent-specific integration recipes.
