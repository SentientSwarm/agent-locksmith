# Agent Locksmith — v2 Roadmap

**Status:** Draft for kickoff
**Supersedes:** `docs/v1/SPEC.md` (M0), `docs/v1/plans/*` (original M1–M4 roadmap)
**Authors:** [you]
**Last updated:** 2026-04-27 (rev. 3)

---

## 1. Vision

Agent Locksmith is the **credential and identity substrate** for AI agents that need to call external services. It sits between an agent and the upstream APIs (REST tools, inference endpoints, internal services), holds the credentials, enforces per-agent authorization, and produces a governance-grade audit trail of every call.

The agent never possesses the credentials it uses. The operator manages identity and policy through a first-class admin surface. The deployment is a single Rust binary plus a SQLite file — no external dependencies, no cloud sync, no opinion on what kind of agent you run.

**What Locksmith is not.** Not an LLM gateway (that's the inference platform's territory — Kamiwaza for enterprise, LiteLLM proxy or similar for those who run one; Locksmith proxies to whichever inference endpoint exists and treats it as just another tool). Not a prompt-injection scanner (that's LlamaFirewall's territory; Locksmith composes with it at a different boundary — see below). Not a network egress controller (that's Pipelock's territory; Locksmith and Pipelock are layered defenses — Locksmith authenticates and credentials every outbound call, Pipelock controls egress for internet-bound traffic). The discipline is to deepen at the credential-and-identity layer rather than expanding outward into adjacent categories.

**How Locksmith composes with cognitive scanners (LlamaFirewall and similar).** LlamaFirewall is an in-process library the agent imports and calls during its reasoning loop — scanning user inputs and tool results before they reach the model, scanning model outputs before they're acted on. Locksmith is a network service the agent calls when it needs to make a credentialed outbound HTTP request. These boundaries don't overlap and shouldn't be stacked: cognitive scanning belongs in the agent's process where it can act on reasoning context; credential injection and identity belong in a separate process so the agent never holds the keys. They run in parallel — both present in a hardened deployment, neither in the other's path.

**Wire-format-agnostic by design.** Locksmith proxies whatever the agent sends to whatever the upstream expects, byte-for-byte. Provider compatibility is not a Locksmith concern. If a service speaks HTTP and accepts a credential in a header, Locksmith can front it. The OpenAI-compatible wire format that Anthropic, OpenAI, Ollama, LM Studio, LiteLLM, vLLM, TGI, and others speak (each with their own dialect) is opaque to Locksmith — it forwards bytes and stays out of the request schema. This is what lets Locksmith remain useful as the inference ecosystem evolves.

## 2. Customers

Three audiences, served by the same product:

**Hardened agent operators.** Run Locksmith as part of an Ansible-managed, network-segmented deployment (e.g., `openclaw-hardened`). Care about: deploy-time secret injection, systemd integration, composition with Pipelock and LlamaFirewall, per-agent blast radius. This is the proving ground.

**Homelab and small-team operators.** Run multiple agent platforms (OpenClaw, Hermes, Pi, custom) on shared infrastructure and want a single credential layer underneath all of them. Care about: agent-platform-agnostic interface, simple admin CLI, working defaults, GitOps-friendly export. This is the audience that validates Locksmith is genuinely standalone.

**Kamiwaza enterprise deployments.** Multi-tenant agent infrastructure where credential hygiene, audit, and per-agent identity are governance requirements. Care about: persistent audit log, per-agent scoping, mTLS, integration with existing secret backends. This is the audience that validates Locksmith is enterprise-credible.

The features that matter for personal use (per-agent identity, scoped tools, audit) are the same features enterprise buyers ask about under different names (multi-tenancy, RBAC, compliance logs). The product is one product.

## 3. Use Cases

Each use case is a real situation a customer is in. Requirements (§4) are derived from these.

### UC-1: Deploy-time agent registration via Ansible
An operator deploys an OpenClaw agent via Ansible. The playbook calls Locksmith's admin interface to register the agent with a name, a tool allowlist, and a metadata blob. Locksmith returns an agent token. The playbook writes the token into the agent's config and starts the agent. The agent calls Locksmith for tools without ever holding upstream credentials.

### UC-2: Self-service rotation by an agent
A long-running Hermes agent's token is approaching expiration. The agent calls Locksmith to rotate its own token, receives a new one, and continues operating. No operator involvement. No downtime. The old token is invalidated immediately.

### UC-3: Self-service status retrieval
An agent boots and asks Locksmith what tools it can see, what its token expires, and whether it's still active. The agent uses this to decide whether to proceed or alert.

### UC-4: Operator-initiated revocation
An operator suspects an agent has been compromised. They use the Locksmith CLI to revoke the agent's token. The next request from that token returns 401. The audit log shows the revocation event and any subsequent denied requests. The operator can later mint a new bootstrap token and re-onboard a replacement agent under a new identity.

### UC-5: Bootstrap token for self-service onboarding
An operator wants to onboard a new agent without writing the credential into config. They mint a single-use bootstrap token via the CLI, hand it to whoever's deploying the agent (or paste it into a deploy script), and the agent presents it during `register` to receive its real credential. The bootstrap token is consumed on first use and cannot be reused.

### UC-6: Inference traffic with credential separation
An agent calls a chat completion endpoint (Anthropic, OpenAI, Kamiwaza, Ollama, LM Studio, or any other OpenAI-compatible upstream) through Locksmith. Streaming responses (SSE) pass through to the agent without buffering. Long generation times do not trip request timeouts. The agent never sees the upstream API key. Whether the upstream is a cloud provider or a local inference proxy, Locksmith's role is the same: inject the credential, route the request, audit the call.

### UC-7: Tool discovery as a function of identity
An agent calls `GET /tools` and sees only the tools its identity is allowed to access *and* for which a credential is configured. A different agent with a different scope sees a different list. Operators see all configured tools regardless of allowlist.

### UC-8: Governance audit query
A compliance reviewer asks "which agents called the GitHub API in the last 30 days, and what was the response status distribution?" The operator runs a query against Locksmith's audit log and gets a structured answer. No credential values appear in the output.

### UC-9: Composed deployment with Pipelock
A request from an agent flows: agent → Locksmith (authenticates agent, injects credential) → either Pipelock (egress DLP, domain allowlist) → internet, or directly to a LAN service. Locksmith is in the path for every authenticated call regardless of destination; Pipelock is in the path only for internet-bound traffic. Per-tool configuration determines which path each tool takes. Pipelock cannot see the credential because it's already injected by Locksmith and TLS-terminated at the upstream — Locksmith and Pipelock are doing different jobs at different layers.

### UC-10: Backup, recovery, and inspection of agent state
An operator wants to back up the agent fleet, inspect it in version control, or recover from a corrupted database. They export Locksmith's agent state to YAML, commit it to git, and can later re-import or use it as audit material.

### UC-11: Remote management
A platform engineer manages Locksmith on a remote host without SSH. They use the Locksmith HTTP admin API over HTTPS with operator credentials to register agents, query audit logs, and rotate tokens. The admin API is on a separate listener from agent traffic.

### UC-12: mTLS-authenticated agents
A high-security deployment requires that agents authenticate to Locksmith via mutual TLS, not bearer tokens. Operators configure Locksmith to accept mTLS. Agents present client certificates issued by a trusted CA; the certificate identity maps to an agent record. Bearer-token agents continue to work during migration if the operator chooses.

### UC-13: Mixed-destination inference
An operator runs LM Studio locally for some models and wants direct cloud-provider access for others. They configure two Locksmith tool entries: one pointing at LM Studio (`egress: direct`, LAN-bound, no Pipelock involvement) and one pointing at Anthropic (`egress: proxied`, internet-bound, transits Pipelock). Each tool entry has its own credential and its own egress treatment. Agents call the appropriate tool depending on which model class they need. The operator's mental model is "one tool entry per destination policy," not "one tool entry per nominal upstream."

## 4. Requirements

Numbered requirements. Each must be satisfied by some milestone. Detailed FRs/NFRs and traceability matrix come out of the design phase.

### Functional

- **R-F1.** Locksmith proxies HTTP requests from agents to configured upstream tools, injecting per-tool credentials, without the agent presenting any upstream credential.
- **R-F2.** Tools are configured statically in YAML (name, upstream URL, auth header and template, timeouts, `egress` flag selecting direct or proxied routing).
- **R-F3.** Each agent has a unique identity, an authentication credential (bearer token, later optionally mTLS), an optional tool allowlist, an optional tool denylist, optional metadata, optional expiration, and an explicit revocation state.
- **R-F4.** Locksmith exposes a self-service API for agents: `register` (with bootstrap token), `status`, `rotate`, `deregister`. An agent can only operate on its own record.
- **R-F5.** Locksmith exposes an operator API for cross-cutting management: list/get/modify/revoke any agent, mint and manage bootstrap tokens, query audit, list configured tools, view system status.
- **R-F6.** Tool discovery (`GET /tools`) returns only tools that are both (a) in the calling agent's allowed set and (b) configured with a valid credential.
- **R-F7.** Locksmith records every proxied request in a persistent audit log: timestamp, agent identity, tool, upstream host, method/path, response status, latency, policy decision. No credential values appear in the log.
- **R-F8.** Locksmith persists agents, tokens (hashed), bootstrap tokens, and audit records in a local SQLite database. Tools and infrastructure remain in YAML.
- **R-F9.** Operators have a CLI (`locksmith ...`) for all operator operations. The CLI talks to the running daemon over a Unix domain socket.
- **R-F10.** Locksmith optionally exposes the operator API over HTTPS for remote management, on a separate listener from agent traffic, off by default.
- **R-F11.** Bootstrap tokens may be single-use or reusable, scoped to a tool allowlist, and have an expiration. Consumed tokens cannot be reused regardless of policy.
- **R-F12.** Locksmith supports inference workloads: SSE/streaming responses pass through without buffering, configurable per-tool timeouts cover multi-minute generation, request and response size limits are configurable per tool.
- **R-F13.** Locksmith supports per-tool egress routing: `egress: proxied` routes the request through a configurable HTTP CONNECT proxy (typically Pipelock for internet-bound traffic); `egress: direct` routes the request without proxy intermediation (typically for LAN-bound services). The flag describes only the Locksmith→upstream hop; downstream behavior of dispatching upstreams is the upstream's responsibility, not Locksmith's.
- **R-F14.** Operators can export agent state to YAML for backup, version control, or inspection. Export contains no cleartext tokens or credentials.
- **R-F15.** Locksmith supports per-tool response controls: maximum response size, content-type allowlist, optional regex-based response redaction.
- **R-F16.** Locksmith supports mTLS as an alternative or additional agent authentication mechanism, configurable per-deployment via `auth_mode` (bearer, mtls, both). Certificate identity (CN or SAN) maps to an agent record.
- **R-F17.** Locksmith supports pluggable secret backends for upstream credentials: environment variables (default), file-based sealed secrets, with a stable interface for additional backends (Vault, AWS Secrets Manager) added without core changes.
- **R-F18.** Locksmith does not inspect or interpret request payloads to make routing or policy decisions. The `model` field in a chat completion request, for example, is data Locksmith forwards but does not interpret. Per-model routing belongs in tools that already understand model semantics (LM Studio, LiteLLM proxy, Kamiwaza). Per-destination policy is achieved by configuring separate tool entries.

### Non-Functional

- **R-N1.** Single binary distribution. No external runtime dependencies beyond a SQLite file.
- **R-N2.** Credentials are stored at rest only as either (a) environment variable references resolved at startup, (b) sealed-secret backend lookups, or (c) hashed (argon2) for agent and bootstrap tokens. Cleartext credentials never persist to disk in Locksmith's own storage.
- **R-N3.** Credentials are zeroized in memory on drop (`secrecy::SecretString` or equivalent).
- **R-N4.** No credential value ever appears in operational logs, audit logs, error responses, or API responses (cleartext credentials are returned exactly once, at registration or rotation, and never thereafter).
- **R-N5.** Configuration changes via YAML reload (ArcSwap) and database changes via admin operations both take effect without process restart.
- **R-N6.** SSE/streaming proxying must not introduce buffering that delays first-byte more than 100ms beyond upstream first-byte.
- **R-N7.** Agent self-service endpoints enforce that the authenticated agent is the only valid subject; operator endpoints are reachable only with operator credentials and are bindable to a separate listener for blast radius isolation.
- **R-N8.** Locksmith is agent-platform-agnostic: any HTTP-speaking agent (OpenClaw, Hermes, Pi, custom) can use it without Locksmith-specific SDK code.
- **R-N9.** All audit and admin operations have an obvious, deterministic answer to "what was the policy decision and what data was the decision based on" — for compliance defensibility.
- **R-N10.** Operator credentials live in operator-only configuration (filesystem, not database), so the system is recoverable when the database is corrupted or missing.

## 5. Roadmap

Seven milestones. M1 and M2 are specified at implementation depth; M3–M7 are specified at intent and constraint depth.

### M1 — Inference-ready hardening

**Goal:** Locksmith's existing M0 proxy correctly handles inference traffic alongside REST tool traffic.

**In scope:**
- SSE/streaming response passthrough without buffering
- Per-tool configurable request and response timeouts (must accommodate multi-minute generation)
- Per-tool configurable request body size limits
- Rename `cloud:` config field to `egress:` with values `direct` or `proxied`. Backwards-compatibility shim: if `cloud: true` is encountered, treat as `egress: proxied` and emit a deprecation warning. Document the new naming in the config example.
- Verification matrix: Anthropic Messages API, OpenAI Chat Completions, Ollama, LM Studio, Kamiwaza inference endpoint, plus a "generic OpenAI-compatible local proxy" entry (test fixture serves the role; LiteLLM proxy, vLLM, TGI, etc. all fit this shape) — all working as `tools:` entries with credential injection
- Integration test suite covering the matrix; tests against local upstreams (Ollama, LM Studio, fixture) run in default CI; tests against cloud providers gated on environment variables for credentials

**Out of scope:**
- Provider-specific routing logic (Locksmith proxies to whatever the agent calls, byte-for-byte; provider selection is the agent's job, or the upstream's if it's a dispatching proxy)
- Fallback, retry, or budget logic
- Model name translation
- Inspecting request payloads to make routing decisions (per R-F18 and D-11)
- New configuration concepts beyond the `egress:` rename and the per-tool timeout / body size fields

**Acceptance:** Integration tests pass for each provider in the matrix. SSE first-byte latency through Locksmith is within 100ms of upstream first-byte. Long-running (>5min) generations complete without timeout under default config.

**Dependencies:** None beyond M0.

### M2 — Agent identity, scoped authorization, and admin substrate

**Goal:** Replace the single-token model with per-agent identity, persistent state, and a first-class admin surface.

**In scope:**

*Persistence layer:*
- SQLite-backed state store (single file, configurable path)
- Schema for `agents`, `bootstrap_tokens`, `audit` (audit table created here, populated in M3)
- Pluggable authenticator trait (`AgentAuthenticator`) — bearer is the v1 implementation; the trait shape must accommodate mTLS as a future implementation without refactoring callers
- Operator credentials remain in operator-only config file (not database) per R-N10

*Agent data model:*
- `id`, `name` (unique), `description`, `token_hash` (argon2), `tool_allowlist` (JSON array, nullable = all tools), `tool_denylist` (JSON array, nullable = none), `metadata` (JSON, opaque), `registered_at`, `last_used_at`, `expires_at` (nullable), `revoked_at` (nullable, soft delete), `role_id` (nullable, reserved for future)
- Bootstrap token model: `id`, `token_hash`, `scope` (JSON: tool_allowlist, expires, single_use bool), `created_by`, `created_at`, `expires_at`, `used_at`, `used_by_agent_id`

*Admin protocol over Unix socket:*
- Internal service layer that both CLI and (later) HTTP API call into
- Two namespaces: `/admin/agent/*` (agent self-service) and `/admin/operator/*` (cross-cutting). Naming convention preserved even though M2 is socket-only — same shape lands in M4 over HTTPS.

*Agent self-service endpoints:*
- `register` — present a bootstrap token, receive an agent record and cleartext token (returned once)
- `status` — return the calling agent's identity, accessible tools, expiration, limits. No system-wide info.
- `rotate` — invalidate current token, issue a new one (returned once)
- `deregister` — soft-delete the calling agent's record

*Operator endpoints:*
- Agent operations: list, get, register (operator-driven, no bootstrap token required), modify (allowlist, denylist, metadata, expiration), revoke
- Bootstrap token operations: mint, list, revoke
- Tool operations: list configured tools (always operator-only)

*CLI:*
- `locksmith agent register | status | rotate | revoke` (operator commands operate on any agent by id; agent-self commands require an agent token via env var or flag)
- `locksmith bootstrap mint | list | revoke`
- `locksmith tool list`
- All subcommands talk to the daemon over the configured Unix socket

*Authorization rules:*
- Agent self-service endpoints: caller's authenticated identity is the only valid subject. Path parameters identifying "which agent" are not accepted on the agent namespace.
- Operator endpoints: require a valid operator credential. v1 grants all-or-nothing operator access (no fine-grained operator roles); the schema reserves a `scope` field on operator credentials for future extension.
- Tool discovery: filtered by `(allowlist == null OR tool ∈ allowlist) AND tool ∉ denylist AND credential_present`.

*Token rotation lifecycle:*
- Static-via-Ansible flow: operator mints token at deploy time, writes it to agent config; future rotation can be operator-driven or agent-self-service
- Rotation always invalidates the prior token immediately (no grace window in v1; consider adding one in a later milestone if operational pain emerges)

**Out of scope:**
- HTTP admin API (M4)
- Audit log population (M3 — schema lands here, writes happen there)
- mTLS (M6)
- At-rest hardening for upstream credentials (M5)
- Operator roles / fine-grained operator scope
- UI

**Acceptance:** All UC-1, UC-2, UC-3, UC-4, UC-5, UC-7 flows demonstrable via CLI. Per-agent allowlist enforcement verified by integration test. Schema migrations work via embedded migration tool (e.g., `refinery` or `sqlx::migrate!`). Token hashing verified to be argon2 with sane parameters.

**Dependencies:** M1.

### M3 — Governance audit log

**Goal:** Every credentialed call produces a queryable, exportable audit record.

**In scope (intent and constraints):**
- Audit writes happen for proxied requests, agent self-service operations, and operator operations
- Persistence to the SQLite `audit` table from M2
- Optional secondary JSONL sink for log shipping (Loki, Splunk)
- Configurable retention window (time-based or count-based)
- CLI: `locksmith audit tail`, `locksmith audit query` (filter by agent, tool, time window, status)
- Export command (`locksmith export agents --format yaml`) for backup and version-control compatibility per UC-10
- Indexes on `(ts)` and `(agent_id, ts)` for query performance
- Constraint: no credential values, ever, in any audit field

**Out of scope:**
- Real-time streaming of audit events to external systems (defer to operator's log shipping infra)
- Audit log signing / tamper-evidence (could be a future milestone if a customer asks)

**Acceptance:** UC-8 query demonstrable. Retention policy enforced. Export round-trips through git for state inspection.

**Dependencies:** M2.

### M4 — Admin HTTP API

**Goal:** Expose the M2/M3 admin operations over HTTPS for remote management.

**In scope (intent and constraints):**
- Same `/admin/agent/*` and `/admin/operator/*` namespaces over HTTPS
- Bindable to a separate listener (port, address) from agent proxy traffic — enables blast-radius isolation per R-N7
- Off by default; explicit configuration to enable
- TLS-required (no plaintext HTTP for admin)
- Bearer-token authentication for both agents and operators in v1; mTLS support for operators arrives with M6
- Bootstrap token registration flow over HTTP, with the constraint that bootstrap tokens are accepted regardless of `auth_mode` (since pre-authentication, by definition) but only grant the right to register

**Out of scope:**
- mTLS (M6 — adds a second auth mechanism here)
- Operator roles
- UI (separate)

**Acceptance:** UC-11 demonstrable. Admin API can be bound to localhost-only, Tailscale-only, or full network exposure based on deployment config. CLI and HTTP API produce identical results for equivalent operations.

**Dependencies:** M3.

### M5 — Keys-at-rest hardening

**Goal:** Reduce the attack surface for upstream credential storage.

**In scope (intent and constraints):**
- Pluggable `SecretBackend` trait
- Default backend: environment variables (existing M0 behavior)
- File-based sealed-secret backend: encrypted file decrypted at startup with a key from `systemd-creds`, `sd-creds`, or equivalent
- Stable interface for future Vault and AWS Secrets Manager backends (no implementation in M5; just the contract)
- systemd unit hardening directives: `NoNewPrivileges`, `ProtectSystem=strict`, `PrivateTmp`, `ReadWritePaths` minimal, dedicated user
- Honest threat model documentation: what at-rest hardening does and doesn't protect against

**Out of scope:**
- Implementing Vault, AWS Secrets Manager, or other vendor backends (interface only)
- Hardware security module integration

**Acceptance:** Operator can deploy Locksmith without any upstream credential appearing in the systemd unit, environment, or config file readable outside the locksmith user. Threat model doc reviewed and merged.

**Dependencies:** M4 (chronologically — at-rest hardening makes the most sense once the admin surface is in place; not strictly technically dependent).

### M6 — mTLS support

**Goal:** Cryptographic agent and operator identity, not possession-based.

**In scope (intent and constraints):**
- `auth_mode: bearer | mtls | both` configuration
- Certificate validation: configured CA bundle, certificate expiration enforcement, revocation list support
- Identity extraction: certificate CN or configurable SAN field maps to an agent record's `name` or a dedicated `cert_identity` field
- mTLS available for *both* agent traffic and operator traffic (operator-mTLS is at least as important as agent-mTLS, since the operator surface is higher value)
- Audit records the authentication method used for each request (`bearer` vs `mtls`) — useful during migration windows
- Worked deployment example: issuing certificates from a small internal CA (smallstep, easy-rsa, or step-ca)
- `both` mode allows incremental migration: high-value agents get certs first, others stay on bearer, with operator visibility into which is which

**Out of scope:**
- Locksmith acting as its own CA (use external CA — smallstep, internal PKI, etc.)
- SPIFFE / workload identity (could be a future milestone if customer pull justifies it)

**Acceptance:** UC-12 demonstrable. `bearer`, `mtls`, and `both` modes all work. Operator API also supports mTLS. Migration path documented.

**Dependencies:** M2 (pluggable authenticator trait), M4 (admin API to harden), M5 (at-rest hardening, so the strongest authentication isn't fronting weakly-protected secrets).

### M7 — Response-side controls

**Goal:** Application-layer controls on what comes back from upstream, complementary to Pipelock's network-layer DLP.

**In scope (intent and constraints):**
- Per-tool maximum response size (with sensible default; configurable)
- Per-tool content-type allowlist (e.g., GitHub returns `application/json`; reject `text/html` if the upstream is misbehaving or compromised)
- Per-tool optional regex-based response redaction (not a full DLP — covers obvious cases like accidental key echo)
- Constraint: streaming responses (M1) must not be broken by these controls; size and redaction apply to non-streaming responses, with streaming responses subject only to total-size cap if configured

**Out of scope:**
- Schema validation of response bodies
- Content scanning beyond regex (defer to LlamaFirewall or similar)

**Acceptance:** Operator can configure a tool to reject responses >10MB, only `application/json`, and redact strings matching a configured pattern. Existing streaming flows unaffected.

**Dependencies:** M2 (per-agent context for audit of redactions), M3 (audit redaction events).

### Deferred / Out of Scope (with rationale)

- **MCP bridging.** Wait for a real use case. Locksmith's existing path-based proxy already covers the credential-injection-for-HTTP-services case that MCP-over-HTTP would also cover. If MCP becomes dominant, future work might be Locksmith *as* an MCP server, not a bridge.
- **Agent-to-agent (A2A) forwarding.** Different threat model. Agents authenticating to agents is a meaningfully different problem than agents authenticating to upstream APIs. Possibly a sibling project.
- **Inference routing, fallbacks, budgets, rate limiting.** Inference platform territory. For enterprise, Kamiwaza provides this directly. For homelab and other deployments, LiteLLM proxy or similar can be configured as just another tool entry. Locksmith proxies to whichever inference endpoint is in use and does not implement gateway features.
- **Per-model routing or model-aware policy.** Locksmith does not inspect request payloads (R-F18, D-11). If destination policy needs to vary by model, configure separate tool entries per destination class.
- **Cloud sync of agent state across deployments.** Solved by Ansible / GitOps for the audiences Locksmith targets. Re-solving would add a sync layer and a cloud service that doesn't fit the single-binary model.
- **Web UI.** Genuinely useful, but the CLI and HTTP API cover capability. UI is a usability layer that can lag and possibly live as a sibling project.
- **Operator role granularity.** v1 operator credentials are all-or-nothing. The schema reserves a `scope` field for future use; expose only when there's a customer asking.

## 6. Working Approach

This is an architectural document. The implementation should follow the team's standing practices, summarized here for explicitness:

**Customer-first.** Each requirement traces to a use case in §3. The traceability matrix produced in detailed design must enforce this.

**London-style TDD.** Outside-in. Write the integration test that exercises the use case first, then drive in toward unit tests as design pressure demands. The M1 integration test matrix (provider-by-provider for inference) is the literal acceptance contract for that milestone — don't write the streaming code first and then test.

**Domain modeling explicit.** The agent / bootstrap token / audit data model in M2 is the spine of the product. Sketch it in `docs/v2/SPEC.md` *before* any M2 code. Get the schema right; migrations are expensive.

**Composability as a feature.** Locksmith does not absorb adjacent functionality. Pipelock does network egress and DLP, LlamaFirewall does prompt-injection scanning, the inference platform (Kamiwaza, LiteLLM proxy, etc.) does provider routing and budgets. Locksmith composes with them at well-defined seams. When in doubt, draw the seam more narrowly.

**Automation over process.** Anything that gets handled manually twice should be automated by the third time. This applies to ops (Ansible) and to development (CI, lint, test).

## 7. Repository Layout

The repo migrates to a v1/v2 split for documentation:

```
docs/
  v1/
    SPEC.md           ← moved from repo root
    plans/
      [previous M1–M4 roadmap docs]
  v2/
    roadmap.md        ← this document
    SPEC.md           ← detailed design, produced from this PRD
    decisions.md      ← see §8
```

Top-level `README.md` updates to reference the v2 docs as canonical and the v1 docs as historical. Code in `src/` continues to evolve forward — the v1/v2 split is for docs only, not for code.

## 8. Decisions

This section captures the architectural decisions that produced this roadmap, with the reasoning preserved. Detailed design should treat these as settled unless a new constraint forces re-litigation.

### D-1: Direction A (credential and identity substrate), not Direction B (full agent gateway)
**Decision:** Locksmith deepens at the credential and identity layer rather than expanding upward into LLM gateway, scanning, or routing.
**Reasoning:** Direction B would require beating mature inference platforms on routing, NeMo/LlamaFirewall on scanning, and the MCP ecosystem on bridging — three uphill fights at once. Direction A leans into what's already differentiated (Pipelock composition, openclaw-hardened integration, Ansible-native) and is a smaller, deeper product.
**Implication:** "Inference routing" is dropped as a milestone. Inference is just another tool type, handled by M1 hardening.

### D-2: SQLite over GitOps/YAML for mutable state
**Decision:** Tools and infrastructure live in YAML (GitOps-managed). Agents, bootstrap tokens, and audit records live in SQLite (daemon-managed).
**Reasoning:** Self-service rotation means the agent process causes state changes. YAML-as-source-of-truth would force "daemon writes its own config" (fights GitOps) or "rotation is operator-only" (contradicts the self-service requirement). SQLite makes the split clean. Audit logs are inherently database-shaped anyway, so a database arrives regardless.
**Mitigation for the GitOps loss:** `locksmith export` produces YAML for backup, version control, or audit material. Operators who want git-backed agent state can run `locksmith export | git commit` on a schedule.

### D-3: Two-namespace admin API
**Decision:** Admin operations split into `/admin/agent/*` (self-service, agent token) and `/admin/operator/*` (cross-cutting, operator credential). Same shape across CLI and HTTP API.
**Reasoning:** Self-scoped operations and cross-cutting operations have fundamentally different risk surfaces. A single admin API with a single token would conflate them. The split also lets deployments bind the operator namespace to a more restricted listener (localhost, Tailscale-only) while exposing the agent namespace alongside proxy traffic.
**Implication:** Agent self-service endpoints take no path parameter for "which agent" — the caller is always the subject. Harder to misuse.

### D-4: Operator-driven and bootstrap-token-driven registration; no open registration
**Decision:** Two registration paths supported: operator-driven (operator credential, mints agent directly) and bootstrap-token-driven (operator pre-mints a bootstrap token, agent presents it). Open registration is not a configuration option.
**Reasoning:** Open registration's failure mode (compromised reachability → ghost agents) is bad enough to foreclose entirely. Bootstrap tokens give the self-service onboarding flow without giving up the gating control.
**Implication:** UC-1 uses operator-driven (Ansible has operator credentials). UC-5 uses bootstrap-token-driven (deploy script gets a token, agent uses it once).

### D-5: Operators in config file, agents in database
**Decision:** Operator credentials live in operator-only configuration on the filesystem. Agent records, tokens, and bootstrap tokens live in the SQLite database.
**Reasoning:** Recovery principal that doesn't depend on the database being healthy. Same pattern as Vault's root token. If the database is corrupted or wiped, operator credentials still work and can rebuild state.

### D-6: Static operator-roles deferred; schema-reserved
**Decision:** v1 operator credentials are all-or-nothing. The schema reserves a `scope` field on the operator credential record for future fine-grained operator roles, but no UI/CLI exposure in v1.
**Reasoning:** Real complexity tax for ambiguous benefit at Locksmith's scales. Don't expose until a customer asks. Schema-reserve to avoid migration when they do.

### D-7: Pluggable authenticator trait from M2
**Decision:** Agent authentication is resolved through an `AgentAuthenticator` trait that takes a request and returns an authenticated agent record. Bearer is the v1 implementation; mTLS becomes a second implementation in M6.
**Reasoning:** Get the layering right in M2 and mTLS is a feature addition, not a refactor. The proxy and admin handlers consume `Agent` from the request context regardless of how it got there.

### D-8: mTLS as a feature flag with three modes
**Decision:** `auth_mode: bearer | mtls | both`. Default `bearer`. `both` mode supports incremental migration.
**Reasoning:** Nobody migrates a fleet to mTLS atomically. Operators need a window where both work and they can verify cert-based auth before turning bearer off. mTLS-only is the strongest stance but should be a deliberate choice, not the default that breaks every existing deployment.

### D-9: mTLS for operators is at least as important as for agents
**Decision:** When mTLS lands in M6, it covers both the agent surface and the operator surface, not just agents.
**Reasoning:** Operator credentials are higher-value targets — they can mint agents and read the audit log. Strongest authentication should cover the highest-value surface.

### D-10: Bootstrap tokens always allowed regardless of `auth_mode`
**Decision:** Bootstrap tokens work in `bearer`, `mtls`, and `both` modes, because they are by definition pre-authentication. They only grant the right to call `register`.
**Reasoning:** mTLS-only mode would otherwise require pre-provisioned certs for bootstrap, defeating the purpose. The registration response can include an issued cert if the operator policy says so — that's a future-conversation problem.

### D-11: Composability over absorption
**Decision:** Locksmith does not implement egress controls (Pipelock's job), prompt-injection scanning (LlamaFirewall's job), or LLM gateway functionality (the inference platform's job — Kamiwaza for enterprise, LiteLLM proxy or similar for those who run one).
**Reasoning:** Each adjacent category has mature tools. Building shallow versions of them inside Locksmith dilutes the product and creates competition with tools that should be allies. The Pipelock integration via the per-tool `egress: proxied` flag and `egress_proxy:` config is the canonical example of how Locksmith composes.
**Corollary:** Locksmith does not inspect request payloads to make routing or policy decisions. The `model` field in a chat completion request, for example, is data Locksmith forwards but does not interpret. Per-model routing belongs in tools that already understand model semantics. Per-destination policy is achieved by configuring separate tool entries — one tool entry per destination policy, not one per nominal upstream service.

### D-12: Revocation is final; replacement requires new bootstrap
**Decision:** A revoked agent record is dead. Re-onboarding a replacement requires a fresh bootstrap token and produces a new agent identity.
**Reasoning:** Cleaner audit trail. "Same name, different identity" is a footgun for auditors. Operators are not blocked — they mint a new bootstrap token and proceed — they're just forced to acknowledge the rotation in the record.

### D-13: Rotation invalidates the old token immediately (no grace window in v1)
**Decision:** When `rotate` is called, the old token becomes invalid the same instant the new token is issued.
**Reasoning:** Simplest model. If operational pain emerges (agents that need to drain in-flight requests on the old token before switching), revisit. Easier to add a grace window than to take it away.

### D-14: Agent-platform-agnostic by design and by documentation
**Decision:** Locksmith presents an HTTP interface that any agent can consume. Documentation leads with "any HTTP-speaking agent (OpenClaw, Hermes, Pi, custom)" rather than with OpenClaw specifically.
**Reasoning:** Standalone-service positioning requires the platform-agnostic framing. The openclaw-hardened deployment is the proving ground, not the only audience.

### D-15: Egress routing is per-tool, not per-model or per-payload
**Decision:** The `egress: direct | proxied` flag is a per-tool YAML setting that describes the Locksmith→upstream hop. It is not derived from request content, not varied by model name, not dynamically computed.
**Reasoning:** Per-payload routing would require Locksmith to inspect request bodies, which violates byte-for-byte transparency (D-11 corollary) and couples Locksmith to provider-specific request schemas. Per-tool routing keeps the policy in the operator's YAML where it can be audited as a single artifact.
**Implication:** When a single nominal upstream needs different egress treatments (e.g., LM Studio with both local and cloud-passthrough models), the operator configures separate tool entries — one per destination policy. The mental model is "one tool entry per destination policy," not "one tool entry per upstream service."

### D-16: Locksmith and Pipelock are layered, not stacked
**Decision:** Locksmith is in the path for every authenticated outbound call regardless of destination. Pipelock is in the path only for internet-bound traffic. LAN-bound traffic (local inference, internal services) transits Locksmith but not Pipelock.
**Reasoning:** Pipelock and Locksmith answer different questions at different layers. Pipelock is a network-layer egress controller — its natural domain is internet-bound traffic, where domain reputation, DLP, and exfiltration patterns matter. Locksmith is an application-layer credential and identity controller — its natural domain is every authenticated call. Forcing all traffic through Pipelock would require carving SSRF allowlist exceptions for LAN destinations, eroding a defense that exists for good reason. Local inference is also where Locksmith's audit log is most valuable (cloud providers give their own audit; local proxies do not), so Pipelock's marginal value-add for LAN traffic is reduced.
**Operator option:** If a deployment wants uniform egress policy (e.g., "every agent call subject to a single allowlist regardless of destination"), the per-tool `egress: proxied` flag supports this — set every tool to `proxied` and configure Pipelock with explicit LAN allowances. The tradeoff is documented in §9: Pipelock's SSRF protection becomes an allowlist rather than default-deny, and local inference incurs proxy overhead for limited audit benefit.
**Implication:** Default for LAN tools is `egress: direct`; default for internet tools is `egress: proxied`. Operators choose otherwise deliberately.

### D-17: Wire-format-agnostic; provider compatibility is a config concern, not a code concern
**Decision:** Locksmith proxies whatever the agent sends to whatever the upstream expects, byte-for-byte. There is no provider-specific code path. New providers, new wire dialects, and new inference proxies are absorbed by writing new YAML entries, not by writing Rust.
**Reasoning:** The inference ecosystem evolves faster than Locksmith should. Coupling Locksmith to a request schema (OpenAI Chat Completions, Anthropic Messages, etc.) creates ongoing maintenance burden and moves Locksmith into territory better served by dedicated inference platforms. Transparency at the wire level keeps Locksmith useful as the ecosystem changes.
**Implication:** The M1 verification matrix includes specific providers as test fixtures, but the codebase has no provider-specific logic. Adding LM Studio, vLLM, TGI, or any future inference proxy is a config exercise.

### D-18: Cognitive scanners and Locksmith compose at different boundaries, in parallel, not in series
**Decision:** Cognitive scanning libraries (LlamaFirewall, NeMo Guardrails, Guardrails AI, similar) operate at the agent's cognitive boundary — imported into the agent's process and invoked during the reasoning loop on inputs, tool results, and outputs. Locksmith operates at the network credential boundary — invoked when the agent needs to make a credentialed outbound call. These are different boundaries in the agent's lifecycle and they compose by both being present, not by being in series on the wire.
**Reasoning:** Cognitive scanning needs reasoning context — the system prompt, the conversation trace, the model's chain of thought. That context lives inside the agent's process. Putting a scanner on the wire after Locksmith means the scanner sees serialized request bodies but loses the reasoning context that makes the scan most valuable (PromptGuard wants user input as the agent received it, AlignmentCheck wants the reasoning trace, CodeShield wants generated code at the moment of generation). Conversely, credential injection needs to be out of the agent's process so the agent never holds the keys — that's Locksmith's whole point. Neither concern fits inside the other.
**Implication:** Locksmith does not specially recognize, integrate with, or front cognitive scanners. The agent imports its scanning library and uses it according to the library's design; the agent uses Locksmith for outbound calls according to Locksmith's design. From Locksmith's perspective, the existence or absence of LlamaFirewall in the agent process is invisible.
**Corollary on what Locksmith expects from any composed middleware:** When middleware *does* sit between Locksmith and an upstream (e.g., a scanning proxy, a routing proxy, an inference platform), Locksmith treats it as an ordinary tool entry — it has an upstream URL, it gets credentials injected by Locksmith, it forwards. The middleware does not hold credentials of its own, does not implement its own agent identity, does not duplicate Locksmith's audit log. If a piece of middleware tries to do those things, it is stepping into Locksmith's territory and the layering breaks down.

## 9. Deployment Patterns

This appendix documents the operational patterns that fall out of the architectural decisions, so operators have a single place to look when wiring Locksmith into their stack.

### 9.1 Layered defense: Locksmith and Pipelock

Locksmith and Pipelock are layered, not stacked (D-16). The mental model:

> Locksmith is in the path for everything authenticated. Pipelock is in the path for everything internet-bound.

This gives uniform credential and identity policy across all calls (Locksmith covers all of them) and uniform egress policy for internet traffic (Pipelock covers all internet calls), without forcing the SSRF allowlist erosion needed to make Pipelock front local services.

```
                  ┌─ internet tool ─→ Locksmith ─→ Pipelock ─→ internet
agent ─→ Locksmith ┤
                  └─ LAN tool ──────→ Locksmith ──────────────→ LAN service
```

The per-tool `egress` flag selects the path:

```yaml
tools:
  - name: anthropic
    upstream: https://api.anthropic.com
    egress: proxied        # → through Pipelock → internet
    auth: { header: x-api-key, value: ${ANTHROPIC_KEY} }

  - name: lmstudio
    upstream: http://localhost:1234
    egress: direct         # → direct to LAN
    # no auth required for default LM Studio
```

### 9.2 The proxy-of-proxy case

When the upstream is itself a dispatching proxy (LM Studio with cloud models, Ollama with cloud passthrough, a local LiteLLM proxy, etc.), Locksmith's `egress` flag applies only to the Locksmith→upstream hop. The upstream's onward dispatch to other destinations is governed by the upstream's own configuration, not Locksmith's. Pipelock cannot see that traffic anyway because it's after TLS termination at the upstream.

If you need destination-level policy enforcement, two patterns work:

**Pattern 1: Separate tool entries per destination class.** Configure one tool entry pointing at the local proxy for local-only models, and a separate tool entry pointing directly at the cloud provider for cloud models. The agent (or its router) chooses which to call. Each tool entry has its own credential and its own egress treatment. This is UC-13 and the recommended pattern.

**Pattern 2: Constrain the upstream.** Configure the local proxy itself to only serve local models, and let cloud-bound traffic go through a different Locksmith tool entry that fronts the cloud provider directly.

Both patterns preserve the architectural invariant: one Locksmith tool entry per destination policy.

### 9.3 The "everything through Pipelock" option

Some operators prefer uniform egress policy across LAN and internet — one place to look, one config to audit, accept the tradeoffs. This is supported but not the default.

To route everything through Pipelock:

1. Set `egress: proxied` on every tool entry, including LAN-bound tools.
2. Configure Pipelock with explicit LAN allowances (host:port pairs) for the local services Locksmith fronts. This carves exceptions to Pipelock's default-deny SSRF protection.
3. Accept that local inference incurs HTTP CONNECT proxy overhead. For SSE traffic, ensure Pipelock is in tunnel mode for these endpoints (no MITM TLS inspection) or accept the latency from inspection.
4. Be aware that Locksmith already provides audit for LAN traffic (R-F7) — Pipelock's marginal value-add for LAN destinations is mostly the consistency of having a single egress audit trail.

### 9.4 Inference platform integration

Locksmith treats inference endpoints as ordinary tools. There is no special "inference" code path. A few patterns operators tend to want:

**Direct-to-provider.** One tool entry per provider (`anthropic`, `openai`, `gemini`, etc.), each with its own credential. Simplest, no intermediate service to operate. Recommended default.

**Through Kamiwaza.** One tool entry pointing at the Kamiwaza inference endpoint. Kamiwaza handles provider routing, auth to upstream providers, and any enterprise-grade gateway functions. Locksmith just fronts Kamiwaza like any other authenticated upstream.

**Through a local LiteLLM proxy or similar.** Same shape as Kamiwaza — one tool entry pointing at the LiteLLM service URL, Locksmith injects whatever credential LiteLLM expects (typically a virtual key), LiteLLM dispatches to providers with the real keys it holds. Useful when an operator already runs LiteLLM for its routing/budget features. Locksmith does not require, recommend, or assume LiteLLM — it works the same way against any OpenAI-compatible upstream.

**Local inference.** One tool entry per local inference proxy (Ollama, LM Studio, vLLM, TGI). `egress: direct`. Optional credential if the local proxy is configured to require one.

The LiteLLM Python library, used inside the agent's process, is invisible to Locksmith — Locksmith sees only the resulting HTTP traffic. Whether the agent uses the library is an agent concern, not a Locksmith concern.

### 9.5 Composition with cognitive scanners (LlamaFirewall and similar)

Cognitive scanners — LlamaFirewall, NeMo Guardrails, Guardrails AI, and similar libraries that detect prompt injection, audit reasoning, or scan generated content — are designed as in-process libraries. The agent imports them and calls them at points in its reasoning loop where their input is available: user messages and tool results before they reach the model, model outputs before they're acted on, generated code before it's executed.

This is a different boundary than Locksmith's. Locksmith protects the network credential boundary; cognitive scanners protect the agent's reasoning boundary. They are present in parallel, both serving the agent, neither in the other's path.

```
                                    ┌── inputs/outputs scanned by
                                    │   cognitive scanner library
                                    │   (LlamaFirewall et al.)
                                    │
Agent (reasoning loop) ─────────────┤
                                    │
                                    │   credentialed outbound
                                    └── HTTP calls go to ──→ Locksmith ──→ upstream
```

**What this means in practice:**

- The agent's code imports the scanning library and integrates it into its request handling. This is an agent design concern, not a Locksmith concern.
- The agent's code calls Locksmith for outbound HTTP. This is a Locksmith concern, not a scanning concern.
- Neither sees the other's work directly. Locksmith does not know whether the agent ran a scan before calling it. The scanner does not know whether the agent will then call Locksmith.
- Audit trails are independent: Locksmith logs network calls; the scanner logs (or doesn't) according to its own design. Operators correlate them externally if they want a unified view.

**Anti-pattern: wrapping a cognitive scanner in a network proxy and putting it between Locksmith and the upstream.** This loses the scanner's most valuable input — reasoning context, system prompts, conversation traces — because by the time the request is on the wire, that context has been serialized into a request body and the scanner can no longer reason about it as part of an agent loop. If a deployment finds itself building a network shim around an in-process scanner, that's a signal the scanner should be moved into the agent's process instead.

**Composed middleware that is on the wire (routing proxies, dispatching upstreams) follows the rules in §9.2 and D-18:** it gets credentials injected by Locksmith, holds none of its own, and does not duplicate Locksmith's identity or audit responsibilities.

---

*End of v2 roadmap. Detailed design (FR/NFR breakdown, traceability matrix, schema migration plan, API contracts) lives in `docs/v2/SPEC.md` and is produced from this document.*
