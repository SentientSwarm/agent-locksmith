# agent-locksmith — user documentation

User-facing documentation for the **agent-locksmith** Rust crate
(the keystone of the layer8-proxy stack).

Content is **evergreen** (reflects the latest-shipped state) and
**not versioned by filename**. Versioned material — PRD, technical
spec — lives in `agents-stack/docs/{prd,spec}/`. This tree distills
that material into what users need to *use* the product.

## Audiences

- **Developers** running `locksmithd` standalone (evaluation,
  embedding in your own deployment system).
- **Operators** running the locksmith CLI against a deployed daemon
  (`locksmith agent register`, `locksmith audit query`, etc.).
- **Agent developers** wiring an agent (hermes, openclaw, custom)
  into a layer8-proxy deployment.

For the production Docker Compose bundle deployment story, see
[`layer8-proxy/docs/user/`](https://github.com/SentientSwarm/layer8-proxy/tree/main/docs/user).

## Tier 1 — get started

| Doc | Audience |
|---|---|
| [getting-started.md](getting-started.md) | Developer first-contact: build, mint operator credential, register agent, make a call. |
| [cli-reference.md](cli-reference.md) | Complete `locksmith` CLI subcommand and flag reference. |
| [architecture.md](architecture.md) | User-level system view: daemon composition, request flow, what state lives where. |

## Tier 2 — concepts (`concepts/`)

User-level mental models distilled from the stack spec at
`agents-stack/docs/spec/v0.2.0.md`:

| Doc | Topic |
|---|---|
| [concepts/kind-taxonomy.md](concepts/kind-taxonomy.md) | model / tool / infra discriminator (Phase E). |
| [concepts/agent-identity-and-acl.md](concepts/agent-identity-and-acl.md) | Per-agent bearer + allowlist + audit. |
| [concepts/trust-boundary.md](concepts/trust-boundary.md) | Who holds what credential, why. |
| [concepts/error-envelope.md](concepts/error-envelope.md) | §4.7.9 wire envelope + Q-8 existence-leak avoidance. |

## Tier 3 — agent integration (`agent-integration/`)

Wiring an agent through a layer8-proxy deployment:

| Doc | Topic |
|---|---|
| [agent-integration/wire-contract.md](agent-integration/wire-contract.md) | What an agent sees: endpoints, headers, error codes, streaming semantics. |
| [agent-integration/openclaw.md](agent-integration/openclaw.md) | Openclaw integration recipe (works out-of-box via `*_BASE_URL`). |
| `agent-integration/hermes.md` | Hermes integration (planned). |
| `agent-integration/skill-reference.md` | `/skill` endpoint spec (planned). |
| `agent-integration/examples/` | curl + Python + TypeScript snippets (planned). |
