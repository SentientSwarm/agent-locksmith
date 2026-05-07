# Getting started (developer first-contact)

This doc is for developers who want to run **agent-locksmith
standalone** — no Docker bundle, no site repo, just the Rust crate and
the daemon. Useful for evaluation, embedding in your own deployment
system, or exercising the codebase.

For the production layer8-proxy bundle deployment story, see
[`layer8-proxy/docs/user/getting-started.md`](https://github.com/SentientSwarm/layer8-proxy/blob/main/docs/user/getting-started.md).

## Prerequisites

- Rust toolchain (1.85+ — agent-locksmith uses edition 2024).
- A C toolchain (cargo + libssl-dev / openssl).
- Optional: `jq`, `curl`.

## Step 1: Build

```bash
git clone git@github.com:SentientSwarm/agent-locksmith.git
cd agent-locksmith
cargo build --release
```

Two binaries land in `target/release/`:

- **`locksmithd`** — the daemon. Reads `--config <path>`, binds the
  agent listener + admin UDS, runs.
- **`locksmith`** — the operator + agent self-service CLI. Talks to
  a running daemon via the admin UDS (default) or admin HTTPS.

## Step 2: Mint an operator credential

The operator credential is what proves you're the operator when
calling admin endpoints (registering agents, putting tool entries,
querying audit, etc.).

```bash
./target/release/locksmith bootstrap-operator --name dev > operators.yaml
```

Output goes to two streams:

- **stdout** — `operators.yaml` content (one operator entry, with
  the secret argon2-hashed). Pipe to a file.
- **stderr** — the cleartext wire token, printed ONCE. Save it now;
  the daemon validates against the hash, never the cleartext.

Sample stderr:

```
✓ Operator credential minted.

  Wire token (save this NOW — cannot be recovered):

    lkop_JJzZehsZbxC41cYZoPFrlg.DkhOj8p7mNbyIOd7xErWBDKSgE3zEnCPPVNMdDbDOn0

  Install on the operator's host:

    export LOCKSMITH_OP_TOKEN='lkop_JJzZehsZbxC41cYZoPFrlg.DkhOj8p7mNbyIOd7xErWBDKSgE3zEnCPPVNMdDbDOn0'
```

Save the token to your shell environment (or sealed-cred store) —
you'll need it in step 5+.

`bootstrap-operator` is offline — it doesn't talk to a daemon. You can
re-run it at any time, but doing so mints a fresh token; the prior
wire token stops working as soon as you replace `operators.yaml`.

## Step 3: Configure the daemon

`config.example.yaml` in this repo is a working minimal config. Copy
it and adjust `operator_credentials_path` to point at your
`operators.yaml` from step 2:

```bash
cp config.example.yaml config.yaml
```

Edit `config.yaml` so it has at least:

```yaml
listen:
  host: "127.0.0.1"
  port: 9200
  auth_mode: bearer
  admin_socket:
    path: "/tmp/locksmith.sock"

operator_credentials_path: "./operators.yaml"

database:
  path: "./locksmith.db"

audit:
  retention_days: 90
  sweep_interval_seconds: 3600
```

## Step 4: Start the daemon

```bash
./target/release/locksmithd --config config.yaml
```

You should see structured-JSON logs on stdout. Leave it running in
this terminal; open a new one for the next steps.

```bash
# In another terminal:
curl -sS http://127.0.0.1:9200/livez
# {"status":"live","uptime_seconds":N}

curl -sS http://127.0.0.1:9200/version
# {"name":"agent-locksmith","version":"2.0.0"}
```

## Step 5: Register an agent

```bash
export LOCKSMITH_OP_TOKEN="lkop_..."  # from step 2

./target/release/locksmith --socket /tmp/locksmith.sock \
    agent register --name dev-agent --allowlist anthropic
```

The CLI prints the agent's bearer token:

```
public_id: yN2vR6jFKNYfIwNjFU2MSA
token:     lk_yN2vR6jFKNYfIwNjFU2MSA.1TJlTmOgmswZYZx_aQHyjaNiugeJjudytNPFJgT9aqM
allowlist: ["anthropic"]
```

Save the bearer for step 6.

## Step 6: Make a call

The seed catalog at `/etc/locksmith/seed/catalog.yaml` has 16 default
providers. Standalone runs pick that path up automatically if it's
present in the filesystem; for a dev box without it, point at the
in-repo `seed/catalog.yaml`:

```bash
LOCKSMITH_SEED_PATH="$PWD/seed/catalog.yaml" \
    ./target/release/locksmithd --config config.yaml &
```

Then call Anthropic (set `ANTHROPIC_API_KEY` in the daemon's env first):

```bash
AGENT_TOKEN="lk_yN2v..."
curl -sS -H "Authorization: Bearer $AGENT_TOKEN" http://127.0.0.1:9200/models
# {"models":[{"name":"anthropic","path":"/api/anthropic","type":"api","description":"..."}, ...]}

curl -sS -X POST http://127.0.0.1:9200/api/anthropic/v1/messages \
    -H "Authorization: Bearer $AGENT_TOKEN" \
    -H "anthropic-version: 2023-06-01" \
    -H "Content-Type: application/json" \
    -d '{"model":"claude-haiku-4-5","max_tokens":40,"messages":[{"role":"user","content":"hi"}]}'
```

If you see a real Anthropic completion, the standalone setup is working.

## What you've actually exercised

The standalone flow above hits all the v2.0.0 invariants:

- **Per-agent bearer + ACL**: the agent's `--allowlist anthropic`
  means it can only reach `/api/anthropic/...`. Try `/api/openai/...`
  with the same bearer — you'll get 403 `tool_not_allowed`.
- **Catalog substrate**: `/models` returns kind=model only, ACL-
  filtered. `/tools` returns kind=tool only.
- **Credential injection**: locksmith reads `ANTHROPIC_API_KEY` from
  its environment at startup and injects `x-api-key: <real-key>` on
  the wire to Anthropic. Your agent never saw the real key.
- **Audit**: every request gets one row.

## What you DON'T get standalone

- **pipelock egress chokepoint** — locksmith goes direct to upstream;
  no DLP, no allowlist enforcement at the network layer. Production
  deploys add pipelock via the layer8-proxy compose bundle.
- **lf-scan prompt/code scanner** — same; opt-in middleware, not
  bundled standalone.
- **Sealed-creds at rest** — your `operators.yaml` and `.env` are
  cleartext on disk (mode 0600 by convention; not enforced). The
  layer8-proxy-site sealed-cred mechanism (systemd-creds /
  openssl-AES) is layered on top in the bundle.
- **Backup automation** — the locksmith DB is just a SQLite file;
  back up `locksmith.db*` like any other application state.

## What's next

- **CLI reference**: [cli-reference.md](cli-reference.md) — every
  subcommand and flag.
- **Architecture**: [architecture.md](architecture.md) — user-level
  view of the daemon's runtime composition.
- **Concepts**: [concepts/](concepts/) — kind taxonomy, agent
  identity + ACL, error envelope, trust boundary.
- **Agent integration recipes**: [agent-integration/](agent-integration/)
  — wiring openclaw, hermes, or a custom agent through locksmith.
- **Production bundle**: [`layer8-proxy`](https://github.com/SentientSwarm/layer8-proxy)
  — Docker Compose with pipelock + lf-scan + sealed-creds infrastructure.

## See also

- [`agents-stack/docs/spec/v0.2.0.md`](https://github.com/SentientSwarm/agents-stack/blob/main/docs/spec/v0.2.0.md) — formal stack spec.
- [`docs/v2/HANDOFF.md`](../v2/HANDOFF.md) — engineering cold-start
  handoff (read before contributing code).
