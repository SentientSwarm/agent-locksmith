# Claude Code Kickoff — agent-locksmith v2

You're picking up `agent-locksmith` to deliver against the v2 roadmap. Read this whole prompt before doing anything else.

## Read first

1. `docs/v2/roadmap.md` — the PRD. This is the spine. §3 (Use Cases), §4 (Requirements), §5 (Roadmap), and §8 (Decisions) are where the answers live. When in doubt, those sections override anything else.
2. `docs/v1/SPEC.md` — what currently ships (M0). Useful for understanding the codebase as-is.
3. `Cargo.toml`, `src/`, `tests/` — the existing implementation.

If the roadmap and the existing code disagree, the roadmap is the target state. Do not change behavior to match the roadmap without an explicit task to do so.

## Repository housekeeping (do this first)

Before any feature work, perform the v1/v2 documentation split described in roadmap §7:

1. Create `docs/v1/` and `docs/v2/`.
2. Move the existing top-level `SPEC.md` to `docs/v1/SPEC.md`.
3. Move existing `docs/plans/*` content into `docs/v1/plans/`.
4. Place the roadmap document at `docs/v2/roadmap.md` (the version you were handed).
5. Update top-level `README.md` to reference `docs/v2/roadmap.md` as the canonical forward-looking doc and `docs/v1/SPEC.md` as the historical implementation contract.
6. Single commit, message: `docs: split v1/v2 documentation`.

Do not move code under v1/v2 directories. The split is for documentation only.

## Working approach

**London-style TDD, outside-in.** Start with the integration test that exercises the use case. Drive in toward unit tests as design pressure demands. Do not write the implementation first and then write tests against it.

**Customer-first.** Every requirement traces to a use case. If you find yourself building something that doesn't trace to a use case in roadmap §3, stop and ask.

**Domain modeling explicit and early.** For M2, sketch the data model in `docs/v2/SPEC.md` *before* writing migration or schema code. Schema choices are the most expensive thing to revisit. Get them reviewed before they harden.

**Composability.** Don't absorb adjacent functionality. If something looks like Pipelock's job, LlamaFirewall's job, or LiteLLM's job, it's not Locksmith's job. See decision D-11.

**Working backwards.** When uncertain, re-read the use case the work serves and ask "would this satisfy the customer's actual situation?" — not "is this technically correct?"

## Engineering standards

- Rust idioms; existing code style. Run `cargo clippy -- -D warnings` and `cargo fmt --check` before any commit.
- `secrecy::SecretString` for anything that might hold a credential. Zeroize on drop. Never `Debug`-print a secret.
- `tracing` for operational logs; structured fields. No credential values in any log line, ever.
- Tests live in `tests/` for integration, `src/**/tests` modules for unit. Integration tests should exercise behavior end-to-end (real HTTP server, real SQLite, no mocks at the boundary).
- Migrations: pick one tool (`refinery` or `sqlx::migrate!`) and stay consistent. Migrations are checked-in source.
- All new modules get rustdoc on public items.

## Start with M1

M1 is "inference-ready hardening" — making the existing M0 proxy correct for inference workloads.

**Acceptance contract** (from roadmap §5, M1):
- Integration test matrix passing for: Anthropic Messages, OpenAI Chat Completions, Ollama, LM Studio, Kamiwaza inference endpoint, plus a generic OpenAI-compatible local proxy fixture (covers LiteLLM proxy, vLLM, TGI shape)
- Local-upstream tests (Ollama, LM Studio, fixture) run in default CI; cloud-provider tests gated on credential env vars
- SSE first-byte latency through Locksmith within 100ms of upstream first-byte
- Long-running (>5min) generations complete under default config
- SSE/streaming passthrough without buffering
- Per-tool configurable request and response timeouts
- Per-tool configurable request body size limits
- `cloud:` config field renamed to `egress:` (values: `direct` | `proxied`) with backwards-compat shim that warns on `cloud:` usage

**Suggested order of attack:**

1. Write the integration test that proxies a streaming chat completion through Locksmith to a stub upstream (test fixture; no real provider key needed for the basic streaming test). Assert SSE chunks arrive at the test client in the same shape and timing as the upstream emits them. *This test will fail.*
2. Make it pass. Identify whatever buffering or timeout in the current proxy breaks streaming. Fix at the smallest reasonable scope.
3. Add the per-tool timeout and body-size config fields. Test that they actually take effect.
4. Rename `cloud:` to `egress:` with values `direct` | `proxied`. Add backwards-compat: if a config has `cloud: true`, treat as `egress: proxied` and log a deprecation warning. Update `config.example.yaml`. Add a test that exercises both old and new field names.
5. Add the local-upstream integration tests: a fixture upstream serving an OpenAI-compatible streaming response, real Ollama if available in CI, real LM Studio if available locally. These run in the default CI lane.
6. Add real-provider integration tests gated on environment variables for credentials (e.g., `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`). Skipped by default in CI but runnable locally and in a credentialed CI lane.
7. Manual verification for Kamiwaza — environment-dependent and doesn't lend itself to public CI.

**What's not in M1:**
- Don't change the YAML config format beyond adding the new per-tool fields and the `cloud:` → `egress:` rename.
- Don't add provider-specific code paths. Locksmith is byte-for-byte transparent (D-17); provider differences are a config concern, not a code concern.
- Don't inspect request payloads to make routing decisions (R-F18, D-11 corollary).
- Don't implement retry, fallback, budget, or per-model routing logic. That's the inference platform's territory (D-11, D-15).
- Don't touch the agent identity or admin surface. That's M2.

## After M1

Stop and check in before starting M2. M2 is the load-bearing milestone — it introduces persistence, the agent data model, and the admin substrate. The data model decisions there compound into everything that follows, so they deserve a design review pass before implementation. Sketch the schema and the authenticator trait shape in `docs/v2/SPEC.md`, then ask for review.

## Conventions for asking questions

If a requirement is ambiguous, ask. Do not invent a resolution.
If a decision in §8 conflicts with what you're being asked, name the decision and the conflict explicitly.
If you find a use case the roadmap doesn't cover, propose adding it rather than building outside the spec.

## Conventions for commits

- One logical change per commit.
- Conventional commits: `feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `chore:`.
- Include the milestone in the commit body when relevant: `M1: SSE passthrough` or similar.
- Tests and the code they cover ship in the same commit when reasonable.

## Conventions for PRs

- Title references the milestone and the requirement(s) satisfied: `M1 (R-F12, R-N6): SSE streaming passthrough`.
- Description includes: which use cases the change advances, which requirements it satisfies, what's deliberately not included, how to verify manually if applicable.
- The traceability matrix in `docs/v2/SPEC.md` updates with every PR that closes a requirement.

---

Begin with the housekeeping (v1/v2 split), then read the roadmap end-to-end, then start on M1's first failing test.
