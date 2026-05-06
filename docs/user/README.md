# agent-locksmith — user documentation

User-facing documentation for the **agent-locksmith** Rust crate (the keystone of the layer8-proxy stack).

Content is **evergreen** (reflects the latest-shipped state) and **not versioned by filename**. Versioned material — PRD, technical spec — lives in `agents-stack/docs/{prd,spec}/`. This tree distills that material into what users need to *use* the product.

## Audiences

- **Agent developers** wiring an agent into a layer8-proxy deployment (point your agent at locksmith's wire contract).
- **Locksmith CLI users** running `locksmith agent register`, `locksmith audit query`, etc.

## Layout

- `getting-started.md` — first contact with locksmith.
- `cli-reference.md` — comprehensive CLI flags and subcommands.
- `architecture.md` — user-level overview of how locksmith fits into the stack.
- `concepts/` — user-level mental models (trust boundary, kind taxonomy, agent identity + ACL, error envelope).
- `agent-integration/` — wire contract + `/skill` reference + worked examples for agent developers.
