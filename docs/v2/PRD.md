# Agent Locksmith v2 — Product Requirements Document

**Status:** Formalized PRD for kickoff
**Source roadmap:** `docs/v2/roadmap.md`
**Detailed design:** `docs/v2/SPEC.md` (produced from this PRD)
**Last updated:** 2026-04-28

This PRD is the formalized product specification derived from `docs/v2/roadmap.md`. It is the canonical artifact for stakeholders who need to understand the product, the audiences, what is being built, and why. Detailed implementation design (FR/NFR breakdown at code depth, traceability matrix, schema migration plan, API contracts) lives in `docs/v2/SPEC.md`.

The numbered identifiers in this document — UC-1 through UC-13, R-F1 through R-F18, R-N1 through R-N10, M1 through M7, D-1 through D-18 — are stable and referenced by traceability matrices and engineering commits. They are preserved verbatim from the roadmap.

## Table of contents

1. Executive summary
2. Product overview
3. Problem statement
4. Goals and non-goals
5. User personas
6. Use cases
7. Functional requirements
8. Non-functional requirements
9. User experience and operator experience
10. Success metrics
11. Milestones and sequencing
12. Assumptions and dependencies
13. Out of scope
14. Risks and resolved decisions
15. Architectural decisions (appendix)

## 1. Executive summary

Agent Locksmith is the credential and identity substrate for AI agents that need to call external services. It is a single Rust binary plus a SQLite file that sits between an agent and the upstream APIs the agent uses (REST tools, inference endpoints, internal services), holds the credentials, enforces per-agent authorization, and produces a governance-grade audit trail of every call. The agent never possesses the credentials it uses.

Locksmith is deliberately narrow. It is not an LLM gateway, not a prompt-injection scanner, and not a network egress controller. Each of those problems is owned by an adjacent tool — Kamiwaza or LiteLLM proxy for inference routing, LlamaFirewall or similar for cognitive scanning, Pipelock for network egress. Locksmith composes with these as peers; it does not absorb them. This discipline is core to the product's identity.

The product serves three audiences with one codebase: hardened agent operators (the proving ground), homelab and small-team operators (the audience that validates Locksmith is genuinely standalone), and Kamiwaza enterprise deployments (the audience that validates Locksmith is enterprise-credible). The features personal users want (per-agent identity, scoped tools, audit) are the same features enterprise buyers ask about under different names (multi-tenancy, RBAC, compliance logs).

v2 delivers seven milestones: M1 inference-ready hardening, M2 agent identity and admin substrate, M3 governance audit log, M4 admin HTTP API, M5 keys-at-rest hardening, M6 mTLS support, M7 response-side controls. M1 and M2 are specified at implementation depth; M3–M7 at intent and constraint depth.

## 2. Product overview

### 2.1 Document title and version

- **Title:** Agent Locksmith v2 — Product Requirements Document
- **Status:** Draft for kickoff
- **Supersedes:** `docs/v1/SPEC.md` (M0), `docs/v1/plans/*` (original M1–M4 roadmap)

### 2.2 Product summary

Agent Locksmith v2 is a credential and identity substrate, delivered as a single Rust binary plus a local SQLite file. It exposes:

- An HTTP proxy interface that agents use to call upstream tools without holding upstream credentials.
- An admin interface (Unix domain socket in v1; HTTPS in M4) that operators use to register agents, mint bootstrap tokens, query audit, and manage policy.
- A self-service API on the same admin surface that agents use to register (with a bootstrap token), check status, rotate their own credentials, and deregister.

State is partitioned. Tools and infrastructure live in YAML, GitOps-managed. Agents, bootstrap tokens, and audit records live in SQLite, daemon-managed. Operator credentials live in operator-only configuration (filesystem, not database) so the system is recoverable when the database is corrupted or missing.

The product is wire-format-agnostic. Locksmith proxies whatever the agent sends to whatever the upstream expects, byte-for-byte. Provider compatibility — OpenAI Chat Completions, Anthropic Messages, Ollama, LM Studio, Kamiwaza, LiteLLM, vLLM, TGI — is a configuration concern, not a code concern. New providers and new wire dialects are absorbed by writing new YAML entries, not by writing Rust.

### 2.3 What Locksmith is not

This section is prominent because the product's discipline against scope creep is core to its identity.

- **Not an LLM gateway.** That is the inference platform's territory — Kamiwaza for enterprise, LiteLLM proxy or similar for those who run one. Locksmith proxies to whichever inference endpoint exists and treats it as just another tool.
- **Not a prompt-injection scanner.** That is LlamaFirewall's territory (and similar: NeMo Guardrails, Guardrails AI). Locksmith composes with cognitive scanners at a different boundary — they run in parallel inside the agent's process, while Locksmith operates as a separate network service. Neither is in the other's path.
- **Not a network egress controller.** That is Pipelock's territory. Locksmith and Pipelock are layered defenses: Locksmith authenticates and credentials every outbound call regardless of destination; Pipelock controls egress for internet-bound traffic.

The discipline is to deepen at the credential-and-identity layer rather than expanding outward into adjacent categories.

## 3. Problem statement

AI agents that take actions in the world — calling REST APIs, hitting inference endpoints, talking to internal services — need credentials to do so. Today, those credentials are typically embedded in the agent's process, in environment variables, in config files, or in code. This produces several problems:

1. **Credential blast radius.** Any compromise of the agent process compromises every credential it holds. There is no per-agent identity to revoke; the credential and the agent are the same thing.
2. **No governance audit.** When a credential is shared across agent instances or hard-coded in deployment artifacts, there is no defensible answer to "which agent called what, and when, and with which authorization." Compliance reviewers cannot reconstruct a call.
3. **No scoped authorization.** An agent that holds a credential holds the credential's full scope. Per-agent allowlists, per-agent rate limits, and per-agent revocation are not possible without an external policy layer.
4. **Manual rotation pain.** Rotating a credential means redeploying every agent that holds it. Long-running agents, in particular, force operators to choose between rotation hygiene and uptime.
5. **Tight coupling to provider ecosystems.** Agents that hardcode provider SDKs and credential layouts cannot easily switch between cloud and local inference, between providers, or between regions.

Adjacent tools partially address these — secret managers (Vault, AWS Secrets Manager) hold credentials at rest, inference platforms (Kamiwaza, LiteLLM) handle provider abstraction, network controllers (Pipelock) handle egress — but none of them provides the per-call, per-agent, identity-and-credential substrate that closes the loop. Operators today either accept the credential blast radius or build a bespoke proxy layer themselves.

Agent Locksmith addresses this gap with a single binary that any HTTP-speaking agent can use, deployable in a homelab in five minutes and credible enough for enterprise governance.

## 4. Goals and non-goals

### 4.1 Business goals

- Establish Agent Locksmith as the default credential and identity substrate for the three target audiences (hardened operators, homelab/small-team, Kamiwaza enterprise) without sacrificing the same-product positioning.
- Validate enterprise-credibility through the Kamiwaza deployment path while remaining genuinely standalone for homelab and small-team operators.
- Maintain composability with adjacent tools (Pipelock, LlamaFirewall, inference platforms) as a structural feature, not a marketing claim — Locksmith should remain useful as the surrounding ecosystem evolves.
- Deliver v2 milestones in sequence (M1 through M7) with each milestone independently usable.

### 4.2 User goals

- **Operators** can deploy Locksmith with a single binary and a SQLite file, manage agents through a CLI or remote HTTP admin API, and produce defensible audit trails for compliance.
- **Agents** can call upstream tools without ever holding upstream credentials, register and rotate their own credentials self-service via bootstrap tokens, and discover their authorized tool set as a function of their identity.
- **Compliance reviewers** can answer "which agent called what, when, and what was the policy decision" against a queryable, retention-controlled log with no credential values present.

### 4.3 Non-goals

Drawn from roadmap §1 ("What Locksmith is not") and §5 ("Deferred / Out of Scope"). These are explicit non-goals for v2 and beyond unless customer pull justifies revisiting.

- **No LLM gateway functionality.** No provider routing, no fallbacks, no retry logic, no model-name translation, no per-model policy.
- **No prompt-injection scanning, cognitive content scanning, or reasoning-trace inspection.** Cognitive scanners run in-process inside the agent; Locksmith does not front them or compose with them in series.
- **No network egress control beyond per-tool routing.** Locksmith does not implement domain allowlisting, DLP, or SSRF protection. The `egress: proxied` flag delegates to Pipelock for that.
- **No payload inspection.** Locksmith does not interpret request bodies to make routing or policy decisions. Per-destination policy is achieved by configuring separate tool entries (R-F18, D-11, D-15).
- **No MCP bridging in v2.** Wait for a real use case. Existing path-based proxy already covers credential injection for HTTP services.
- **No agent-to-agent (A2A) forwarding.** Different threat model; possibly a sibling project.
- **No cloud sync of agent state.** Solved by Ansible / GitOps for the audiences Locksmith targets.
- **No web UI in v2.** CLI and HTTP API cover the capability surface.
- **No fine-grained operator role granularity in v1.** Schema reserves a `scope` field; expose only when a customer asks (D-6).
- **No Locksmith as its own CA.** Use external CA (smallstep, internal PKI) for mTLS in M6.
- **No SPIFFE / workload identity in v2.** Defer until customer pull justifies it.
- **No HSM integration in v2.**
- **No audit log signing or tamper-evidence in v2.** Could be a future milestone if a customer asks.

## 5. User personas

Three audiences served by one product. Same features under different names.

### 5.1 Key user types

- Hardened agent operators
- Homelab and small-team operators
- Kamiwaza enterprise deployers
- Compliance and audit reviewers (cross-cutting)
- AI agents themselves (programmatic users)

### 5.2 Persona details

#### 5.2.1 Hardened agent operator

**Role:** Platform engineer running an Ansible-managed, network-segmented deployment such as `openclaw-hardened`.

**Pains:** Need deploy-time secret injection without leaving credentials in playbooks; need systemd integration and per-agent blast radius isolation; need composition with Pipelock and LlamaFirewall already deployed in the environment; want strong defaults but precise control when they need to override.

**Desired outcomes:** Mint a bootstrap token in the playbook, hand it to the agent at deploy time, never touch the upstream credential outside the operator surface. Audit log answers compliance questions without further tooling. Locksmith integrates as an ordinary systemd unit with hardened directives.

**Why this audience:** Proving ground for the product. If Locksmith works here, it has earned the right to be used by less hostile environments.

#### 5.2.2 Homelab and small-team operator

**Role:** Solo or small-team operator running multiple agent platforms (OpenClaw, Hermes, Pi, custom) on shared infrastructure.

**Pains:** Wants a single credential layer underneath all agents regardless of which platform spawned them; wants simple admin CLI; wants working defaults; wants GitOps-friendly export so the agent fleet is inspectable in version control.

**Desired outcomes:** Agent-platform-agnostic interface — any HTTP-speaking agent can use Locksmith with no Locksmith-specific SDK. CLI commands map to obvious operations (`locksmith agent register`, `locksmith bootstrap mint`, `locksmith audit query`). `locksmith export` produces YAML they can commit to git.

**Why this audience:** Validates that Locksmith is genuinely standalone. If it can only run inside `openclaw-hardened`, it isn't the substrate it claims to be.

#### 5.2.3 Kamiwaza enterprise deployer

**Role:** Platform team deploying agent infrastructure inside an enterprise where credential hygiene, audit, and per-agent identity are governance requirements.

**Pains:** Needs persistent, queryable audit log; needs per-agent scoping that maps onto multi-tenancy boundaries; needs mTLS for agent and operator identity; needs integration with existing secret backends (Vault, AWS Secrets Manager).

**Desired outcomes:** mTLS-authenticated agents and operators, pluggable secret backend (Vault interface in particular), audit log compatible with existing log shipping (Loki, Splunk via JSONL secondary sink), retention policy enforceable in product.

**Why this audience:** Validates that Locksmith is enterprise-credible. The features that matter for personal use (per-agent identity, scoped tools, audit) are the same features enterprise buyers ask about under different names (multi-tenancy, RBAC, compliance logs). One product, two framings.

#### 5.2.4 Compliance and audit reviewer

**Role:** Cross-cutting. May be internal (security team) or external (auditor). Does not deploy or configure Locksmith but consumes its audit output.

**Pains:** Needs deterministic, defensible answers to "which agent called what, when, with what authorization, and with what response." No credential values may appear in any output they receive. Needs to query by agent, tool, time window, and status.

**Desired outcomes:** A CLI or API query yields the answer in seconds. The output is exportable and structured. R-N9 (deterministic policy decision attribution) is the contract that backs this.

#### 5.2.5 AI agent (programmatic user)

**Role:** The agent process itself. Calls Locksmith for outbound HTTP. Self-service registers via bootstrap token, rotates its own credentials, queries its own status.

**Pains:** Cannot hold long-lived credentials safely; cannot afford operator involvement on every credential rotation; needs to know what tools it can see at boot to decide whether to proceed.

**Desired outcomes:** HTTP interface that any HTTP client can hit. No SDK requirement. Self-service endpoints that accept the agent's own token only — no path parameter for "which agent" (D-3).

### 5.3 Role-based access

Two roles in v1:

- **Agent.** Authenticated via bearer token (M2) or mTLS (M6). Can call proxied tool endpoints scoped to its allowlist/denylist. Can call agent self-service admin endpoints (`/admin/agent/*`) but only operating on its own record.
- **Operator.** Authenticated via operator credential stored in operator-only configuration. Can call all admin endpoints (`/admin/agent/*` and `/admin/operator/*`). Operator credential is all-or-nothing in v1 (D-6); schema reserves a `scope` field for future fine-grained operator roles.

Bootstrap tokens are not a role; they are pre-authentication artifacts that grant the right to call `register` exactly once (or repeatedly within scope, per token policy) and nothing else (D-10).

## 6. Use cases

Drawn verbatim from roadmap §3. Each requirement (§7, §8) traces to one or more of these.

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

## 7. Functional requirements

Each requirement is identified by a stable ID (R-Fn) and traces to one or more use cases. Detailed FR breakdowns and the full traceability matrix live in `docs/v2/SPEC.md`.

- **R-F1.** Locksmith proxies HTTP requests from agents to configured upstream tools, injecting per-tool credentials, without the agent presenting any upstream credential. *(Priority: must-have. Traces to: UC-1, UC-6, UC-9, UC-13.)*

- **R-F2.** Tools are configured statically in YAML (name, upstream URL, auth header and template, timeouts, `egress` flag selecting direct or proxied routing). *(Priority: must-have. Traces to: UC-6, UC-9, UC-13.)*

- **R-F3.** Each agent has a unique identity, an authentication credential (bearer token, later optionally mTLS), an optional tool allowlist, an optional tool denylist, optional metadata, optional expiration, and an explicit revocation state. *(Priority: must-have. Traces to: UC-1, UC-3, UC-4, UC-7, UC-12.)*

- **R-F4.** Locksmith exposes a self-service API for agents: `register` (with bootstrap token), `status`, `rotate`, `deregister`. An agent can only operate on its own record. *(Priority: must-have. Traces to: UC-2, UC-3, UC-5.)*

- **R-F5.** Locksmith exposes an operator API for cross-cutting management: list/get/modify/revoke any agent, mint and manage bootstrap tokens, query audit, list configured tools, view system status. *(Priority: must-have. Traces to: UC-1, UC-4, UC-5, UC-7, UC-8, UC-11.)*

- **R-F6.** Tool discovery (`GET /tools`) returns only tools that are both (a) in the calling agent's allowed set and (b) configured with a valid credential. *(Priority: must-have. Traces to: UC-7.)*

- **R-F7.** Locksmith records every proxied request in a persistent audit log: timestamp, agent identity, tool, upstream host, method/path, response status, latency, policy decision. No credential values appear in the log. *(Priority: must-have. Traces to: UC-4, UC-8, UC-9.)*

- **R-F8.** Locksmith persists agents, tokens (hashed), bootstrap tokens, and audit records in a local SQLite database. Tools and infrastructure remain in YAML. *(Priority: must-have. Traces to: UC-1, UC-4, UC-5, UC-8, UC-10.)*

- **R-F9.** Operators have a CLI (`locksmith ...`) for all operator operations. The CLI talks to the running daemon over a Unix domain socket. *(Priority: must-have. Traces to: UC-1, UC-4, UC-5, UC-8.)*

- **R-F10.** Locksmith optionally exposes the operator API over HTTPS for remote management, on a separate listener from agent traffic, off by default. *(Priority: must-have for M4. Traces to: UC-11.)*

- **R-F11.** Bootstrap tokens may be single-use or reusable, scoped to a tool allowlist, and have an expiration. Consumed tokens cannot be reused regardless of policy. *(Priority: must-have. Traces to: UC-5.)*

- **R-F12.** Locksmith supports inference workloads: SSE/streaming responses pass through without buffering, configurable per-tool timeouts cover multi-minute generation, request and response size limits are configurable per tool. *(Priority: must-have for M1. Traces to: UC-6, UC-13.)*

- **R-F13.** Locksmith supports per-tool egress routing: `egress: proxied` routes the request through a configurable HTTP CONNECT proxy (typically Pipelock for internet-bound traffic); `egress: direct` routes the request without proxy intermediation (typically for LAN-bound services). The flag describes only the Locksmith→upstream hop; downstream behavior of dispatching upstreams is the upstream's responsibility, not Locksmith's. *(Priority: must-have. Traces to: UC-9, UC-13.)*

- **R-F14.** Operators can export agent state to YAML for backup, version control, or inspection. Export contains no cleartext tokens or credentials. *(Priority: must-have for M3. Traces to: UC-10.)*

- **R-F15.** Locksmith supports per-tool response controls: maximum response size, content-type allowlist, optional regex-based response redaction. *(Priority: must-have for M7. Traces to: UC-9 (defense-in-depth complement).)*

- **R-F16.** Locksmith supports mTLS as an alternative or additional agent authentication mechanism, configurable per-deployment via `auth_mode` (bearer, mtls, both). Certificate identity (CN or SAN) maps to an agent record. *(Priority: must-have for M6. Traces to: UC-12.)*

- **R-F17.** Locksmith supports pluggable secret backends for upstream credentials: environment variables (default), file-based sealed secrets, with a stable interface for additional backends (Vault, AWS Secrets Manager) added without core changes. *(Priority: must-have for M5. Traces to: UC-1, UC-9 (operational hardening).)*

- **R-F18.** Locksmith does not inspect or interpret request payloads to make routing or policy decisions. The `model` field in a chat completion request, for example, is data Locksmith forwards but does not interpret. Per-model routing belongs in tools that already understand model semantics (LM Studio, LiteLLM proxy, Kamiwaza). Per-destination policy is achieved by configuring separate tool entries. *(Priority: must-have. Traces to: UC-6, UC-13. Architectural invariant; see D-11, D-15, D-17.)*

## 8. Non-functional requirements

- **R-N1.** Single binary distribution. No external runtime dependencies beyond a SQLite file.

- **R-N2.** Credentials are stored at rest only as either (a) environment variable references resolved at startup, (b) sealed-secret backend lookups, or (c) hashed (argon2) for agent and bootstrap tokens. Cleartext credentials never persist to disk in Locksmith's own storage.

- **R-N3.** Credentials are zeroized in memory on drop (`secrecy::SecretString` or equivalent).

- **R-N4.** No credential value ever appears in operational logs, audit logs, error responses, or API responses (cleartext credentials are returned exactly once, at registration or rotation, and never thereafter).

- **R-N5.** Configuration changes via YAML reload (ArcSwap) and database changes via admin operations both take effect without process restart, *except* for listener-shape changes (`auth_mode`, listener port, TLS certificate paths), which require a restart to rebind the listener under the new shape.

- **R-N6.** SSE/streaming proxying must not introduce buffering that delays first-byte more than 100ms beyond upstream first-byte.

- **R-N7.** Agent self-service endpoints enforce that the authenticated agent is the only valid subject; operator endpoints are reachable only with operator credentials and are bindable to a separate listener for blast radius isolation.

- **R-N8.** Locksmith is agent-platform-agnostic: any HTTP-speaking agent (OpenClaw, Hermes, Pi, custom) can use it without Locksmith-specific SDK code.

- **R-N9.** All audit and admin operations have an obvious, deterministic answer to "what was the policy decision and what data was the decision based on" — for compliance defensibility.

- **R-N10.** Operator credentials live in operator-only configuration (filesystem, not database), so the system is recoverable when the database is corrupted or missing.

## 9. User experience and operator experience

### 9.1 Entry points

- **Operator first contact (CLI).** `locksmith --help` exposes the full operator surface. First-run experience: install binary, drop a YAML config in the conventional location, run `locksmith serve`, then `locksmith agent register --name foo --tool-allowlist '...'` to mint the first agent.
- **Operator first contact (HTTPS, M4 onward).** Same admin surface over HTTPS once `admin_http` is configured. Off by default; explicit opt-in.
- **Agent first contact (bootstrap).** Agent receives a bootstrap token from a deploy artifact (Ansible variable, deploy script, env var). Agent calls `POST /admin/agent/register` with the bootstrap token in the request and receives its own agent token. The bootstrap token is consumed.
- **Agent first contact (operator-driven).** Operator mints the agent record directly via CLI and writes the resulting cleartext token to the agent's config. Agent never sees a bootstrap token in this path.
- **Agent steady state.** Agent makes outbound HTTP calls to Locksmith's proxy interface, presenting its agent token. Locksmith authenticates, authorizes, injects upstream credentials, routes, audits, returns the response.

### 9.2 Core experience

The product surface is minimal and deliberately boring.

- **Tool calls.** Agent issues a normal HTTP request to Locksmith. The request shape matches what the upstream expects, with the agent's authentication token replacing the upstream credential. Locksmith handles the substitution. SSE responses stream back without buffering.
- **Self-service.** Agent calls `register`, `status`, `rotate`, `deregister` against `/admin/agent/*`. The agent never specifies "which agent" — the authenticated identity is always the subject (D-3).
- **Operator administration.** Operator runs `locksmith` subcommands (`agent`, `bootstrap`, `tool`, `audit`, `export`). Each command produces structured output suitable for piping. CLI talks to the daemon over a Unix socket; HTTP API (M4+) speaks the same shapes over HTTPS.
- **Configuration.** Tools and listeners are declared in YAML (`tools:`, `admin_http:`, `egress_proxy:`). Per-tool configuration covers `upstream`, auth header and value template, timeouts, body size limits, response controls (M7), and the `egress` flag.
- **Recovery.** If the SQLite database is corrupted, the operator credential in the config file still authenticates. Operator can repair or replace the database and re-mint agents.

### 9.3 Advanced features

- **mTLS mode (M6).** `auth_mode: bearer | mtls | both`. Supports incremental migration. mTLS covers both agent and operator surfaces. Audit records the authentication method per request.
- **Sealed secret backend (M5).** File-based sealed secrets decrypted at startup using `systemd-creds` or equivalent. Stable interface for future Vault and AWS Secrets Manager backends without core changes.
- **Response controls (M7).** Per-tool response size cap, content-type allowlist, regex-based response redaction. Streaming responses unaffected (size cap may still apply as a total-size limit if configured).
- **Audit query and export (M3).** `locksmith audit tail`, `locksmith audit query` with filters by agent/tool/time/status. `locksmith export agents --format yaml` produces inspectable, version-controllable state with no cleartext credentials.
- **Pipelock composition (always-available).** `egress: proxied` per tool routes via configured HTTP CONNECT proxy; `egress: direct` routes without proxy intermediation. Operators can route everything through Pipelock by setting `egress: proxied` on every tool, accepting the SSRF allowlist tradeoff (see roadmap §9.3).

### 9.4 UI/UX highlights

- **Zero hidden state.** Tools live in YAML (auditable in git); agents, tokens, audit live in SQLite (managed by daemon); operator credentials live in a separate config file (recovery principal). Each piece of state has one home.
- **Two-namespace admin (D-3).** `/admin/agent/*` for self-service (agent token, no path-level "which agent" parameter) and `/admin/operator/*` for cross-cutting management (operator credential). Same shape across CLI and HTTP API.
- **Cleartext credentials returned exactly once.** At registration or rotation. Never retrievable thereafter. Operators that lose the cleartext rotate or re-register.
- **Hot reload.** YAML changes and admin database changes apply without process restart (R-N5). Operators are not punished for fixing a typo. Listener-shape changes (`auth_mode`, port, TLS cert paths) are an explicit exception and require a restart to rebind.
- **Deterministic audit.** Every admin and proxied operation produces a structured record with the policy decision and the input data behind that decision (R-N9). Compliance reviewers get defensible answers.
- **Wire-format-agnostic by default.** New providers and inference proxies are absorbed by writing YAML, not Rust. No provider-specific code paths.

## 10. Success metrics

### 10.1 User-centric metrics

- **Time-to-first-agent.** A new operator can install Locksmith, configure one tool, register one agent, and route a successful proxied call in under 15 minutes from a clean environment.
- **Self-service rotation success rate.** 100% of agent-driven rotation attempts succeed on a healthy daemon. Rotation latency p99 under 200ms.
- **Tool discovery accuracy.** `GET /tools` returns exactly the set defined by `(allowlist == null OR tool ∈ allowlist) AND tool ∉ denylist AND credential_present` — verified by integration test (R-F6).
- **Compliance-query turnaround.** Reviewer can answer a representative governance question (UC-8) in a single CLI invocation, output structured and free of credential values.

### 10.2 Business metrics

- **Audience coverage.** All three audiences (hardened operators, homelab/small-team, Kamiwaza enterprise) deploy v2 in production using the same binary and the same product surface — no audience-specific forks.
- **Composability adoption.** The `egress: proxied` flag and `egress_proxy:` config see use in deployments that also run Pipelock (composed deployment validates D-11, D-16).
- **Inference verification matrix coverage.** M1 ships with passing integration tests against Anthropic, OpenAI, Ollama, LM Studio, Kamiwaza, and a generic OpenAI-compatible local proxy fixture.

### 10.3 Technical metrics

- **SSE first-byte latency overhead.** Locksmith adds less than 100ms to upstream SSE first-byte latency under default configuration (R-N6, M1 acceptance).
- **Long-running generation completion.** Generations exceeding 5 minutes complete without timeout under default per-tool configuration (M1 acceptance).
- **Single-binary footprint.** Distribution is a single Rust binary plus a SQLite file with no other runtime dependencies (R-N1).
- **Credential leak surface.** Zero credential values in operational logs, audit logs, error responses, API responses, or YAML exports (R-N4, R-F14). Validated by automated test.
- **Database recovery.** Operator credential in config file authenticates a fresh daemon against an absent or corrupted database; agents can be re-onboarded without external intervention (R-N10, D-5).
- **Streaming integrity.** Streaming responses pass through Locksmith with no buffering (R-N6). Validated by integration test asserting chunk timing matches upstream.

## 11. Milestones and sequencing

### 11.1 Project estimate

Seven milestones, M1 through M7. M1 and M2 are specified at implementation depth; M3–M7 at intent and constraint depth. The roadmap does not commit calendar estimates; the sequencing and dependency graph are the load-bearing artifact.

### 11.2 Team size

The roadmap and kickoff documents do not commit a team size. The product is structured to be deliverable by a small Rust-fluent team working London-style outside-in TDD with continuous integration.

### 11.3 Suggested phases

#### M1 — Inference-ready hardening

**Goal:** Locksmith's existing M0 proxy correctly handles inference traffic alongside REST tool traffic.

**In scope:**
- SSE/streaming response passthrough without buffering.
- Per-tool configurable request and response timeouts (must accommodate multi-minute generation).
- Per-tool configurable request body size limits.
- Rename `cloud:` config field to `egress:` with values `direct` or `proxied`. Backwards-compatibility shim: if `cloud: true` is encountered, treat as `egress: proxied` and emit a deprecation warning. Document the new naming in the config example.
- Verification matrix: Anthropic Messages API, OpenAI Chat Completions, Ollama, LM Studio, Kamiwaza inference endpoint, plus a "generic OpenAI-compatible local proxy" entry (test fixture serves the role; LiteLLM proxy, vLLM, TGI, etc. all fit this shape) — all working as `tools:` entries with credential injection.
- Integration test suite covering the matrix; tests against local upstreams (Ollama, LM Studio, fixture) run in default CI; tests against cloud providers gated on environment variables for credentials.

**Out of scope:**
- Provider-specific routing logic (Locksmith proxies byte-for-byte; provider selection is the agent's job, or the upstream's if it's a dispatching proxy).
- Fallback, retry, or budget logic.
- Model name translation.
- Inspecting request payloads to make routing decisions (per R-F18 and D-11).
- New configuration concepts beyond the `egress:` rename and the per-tool timeout / body size fields.

**Acceptance:** Integration tests pass for each provider in the matrix. SSE first-byte latency through Locksmith is within 100ms of upstream first-byte. Long-running (>5min) generations complete without timeout under default config.

**Dependencies:** None beyond M0.

**Requirements satisfied:** R-F12, R-F13 (rename only), R-N6.

#### M2 — Agent identity, scoped authorization, and admin substrate

**Goal:** Replace the single-token model with per-agent identity, persistent state, and a first-class admin surface.

**In scope:**

*Persistence layer:*
- SQLite-backed state store (single file, configurable path).
- Schema for `agents`, `bootstrap_tokens`, `audit` (audit table created here, populated in M3).
- Pluggable authenticator trait (`AgentAuthenticator`) — bearer is the v1 implementation; the trait shape must accommodate mTLS as a future implementation without refactoring callers.
- Operator credentials remain in operator-only config file (not database) per R-N10.

*Agent data model:*
- `id`, `name` (unique), `description`, `token_hash` (argon2), `tool_allowlist` (JSON array, nullable = all tools), `tool_denylist` (JSON array, nullable = none), `metadata` (JSON, opaque), `registered_at`, `last_used_at`, `expires_at` (nullable), `revoked_at` (nullable, soft delete), `role_id` (nullable, reserved for future).
- Bootstrap token model: `id`, `token_hash`, `scope` (JSON: tool_allowlist, expires, single_use bool), `created_by`, `created_at`, `expires_at`, `used_at`, `used_by_agent_id`.

*Admin protocol over Unix socket:*
- Internal service layer that both CLI and (later) HTTP API call into.
- Two namespaces: `/admin/agent/*` (agent self-service) and `/admin/operator/*` (cross-cutting). Naming convention preserved even though M2 is socket-only — same shape lands in M4 over HTTPS.

*Agent self-service endpoints:*
- `register` — present a bootstrap token, receive an agent record and cleartext token (returned once).
- `status` — return the calling agent's identity, accessible tools, expiration, limits. No system-wide info.
- `rotate` — invalidate current token, issue a new one (returned once).
- `deregister` — soft-delete the calling agent's record.

*Operator endpoints:*
- Agent operations: list, get, register (operator-driven, no bootstrap token required), modify (allowlist, denylist, metadata, expiration), revoke.
- Bootstrap token operations: mint, list, revoke.
- Tool operations: list configured tools (always operator-only).

*CLI:*
- `locksmith agent register | status | rotate | revoke` (operator commands operate on any agent by id; agent-self commands require an agent token via env var or flag).
- `locksmith bootstrap mint | list | revoke`.
- `locksmith tool list`.
- All subcommands talk to the daemon over the configured Unix socket.

*Authorization rules:*
- Agent self-service endpoints: caller's authenticated identity is the only valid subject. Path parameters identifying "which agent" are not accepted on the agent namespace.
- Operator endpoints: require a valid operator credential. v1 grants all-or-nothing operator access (no fine-grained operator roles); the schema reserves a `scope` field on operator credentials for future extension.
- Tool discovery: filtered by `(allowlist == null OR tool ∈ allowlist) AND tool ∉ denylist AND credential_present`.

*Token rotation lifecycle:*
- Static-via-Ansible flow: operator mints token at deploy time, writes it to agent config; future rotation can be operator-driven or agent-self-service.
- Rotation always invalidates the prior token immediately (no grace window in v1; consider adding one in a later milestone if operational pain emerges).

**Out of scope:**
- HTTP admin API (M4).
- Audit log population (M3 — schema lands here, writes happen there).
- mTLS (M6).
- At-rest hardening for upstream credentials (M5).
- Operator roles / fine-grained operator scope.
- UI.

**Acceptance:** All UC-1, UC-2, UC-3, UC-4, UC-5, UC-7 flows demonstrable via CLI. Per-agent allowlist enforcement verified by integration test. Schema migrations work via embedded migration tool (e.g., `refinery` or `sqlx::migrate!`). Token hashing verified to be argon2 with sane parameters.

**Dependencies:** M1.

**Requirements satisfied:** R-F3, R-F4, R-F5, R-F6, R-F8, R-F9, R-F11, R-N1, R-N2, R-N3, R-N4, R-N5, R-N7, R-N8, R-N10.

#### M3 — Governance audit log

**Goal:** Every credentialed call produces a queryable, exportable audit record.

**In scope (intent and constraints):**
- Audit writes happen for proxied requests, agent self-service operations, and operator operations.
- Persistence to the SQLite `audit` table from M2.
- Optional secondary JSONL sink for log shipping (Loki, Splunk).
- Configurable retention window (time-based or count-based).
- CLI: `locksmith audit tail`, `locksmith audit query` (filter by agent, tool, time window, status).
- Export command (`locksmith export agents --format yaml`) for backup and version-control compatibility per UC-10.
- Indexes on `(ts)` and `(agent_id, ts)` for query performance.
- Constraint: no credential values, ever, in any audit field.

**Out of scope:**
- Real-time streaming of audit events to external systems (defer to operator's log shipping infra).
- Audit log signing / tamper-evidence (could be a future milestone if a customer asks).

**Acceptance:** UC-8 query demonstrable. Retention policy enforced. Export round-trips through git for state inspection.

**Dependencies:** M2.

**Requirements satisfied:** R-F7, R-F14, R-N9.

#### M4 — Admin HTTP API

**Goal:** Expose the M2/M3 admin operations over HTTPS for remote management.

**In scope (intent and constraints):**
- Same `/admin/agent/*` and `/admin/operator/*` namespaces over HTTPS.
- Bindable to a separate listener (port, address) from agent proxy traffic — enables blast-radius isolation per R-N7.
- Off by default; explicit configuration to enable.
- TLS-required (no plaintext HTTP for admin).
- Bearer-token authentication for both agents and operators in v1; mTLS support for operators arrives with M6.
- Bootstrap token registration flow over HTTP, with the constraint that bootstrap tokens are accepted regardless of `auth_mode` (since pre-authentication, by definition) but only grant the right to register.

**Out of scope:**
- mTLS (M6 — adds a second auth mechanism here).
- Operator roles.
- UI (separate).

**Acceptance:** UC-11 demonstrable. Admin API can be bound to localhost-only, Tailscale-only, or full network exposure based on deployment config. CLI and HTTP API produce identical results for equivalent operations.

**Dependencies:** M3.

**Requirements satisfied:** R-F10.

#### M5 — Keys-at-rest hardening

**Goal:** Reduce the attack surface for upstream credential storage.

**In scope (intent and constraints):**
- Pluggable `SecretBackend` trait.
- Default backend: environment variables (existing M0 behavior).
- File-based sealed-secret backend: encrypted file decrypted at startup with a key from `systemd-creds`, `sd-creds`, or equivalent.
- Stable interface for future Vault and AWS Secrets Manager backends (no implementation in M5; just the contract).
- systemd unit hardening directives: `NoNewPrivileges`, `ProtectSystem=strict`, `PrivateTmp`, `ReadWritePaths` minimal, dedicated user.
- Honest threat model documentation: what at-rest hardening does and doesn't protect against.

**Out of scope:**
- Implementing Vault, AWS Secrets Manager, or other vendor backends (interface only).
- Hardware security module integration.

**Acceptance:** Operator can deploy Locksmith without any upstream credential appearing in the systemd unit, environment, or config file readable outside the locksmith user. Threat model doc reviewed and merged.

**Dependencies:** M4 (chronologically — at-rest hardening makes the most sense once the admin surface is in place; not strictly technically dependent).

**Requirements satisfied:** R-F17.

#### M6 — mTLS support

**Goal:** Cryptographic agent and operator identity, not possession-based.

**In scope (intent and constraints):**
- `auth_mode: bearer | mtls | both` configuration.
- Certificate validation: configured CA bundle, certificate expiration enforcement, revocation list support.
- Identity extraction: certificate CN or configurable SAN field maps to an agent record's `name` or a dedicated `cert_identity` field.
- mTLS available for *both* agent traffic and operator traffic (operator-mTLS is at least as important as agent-mTLS, since the operator surface is higher value).
- Audit records the authentication method used for each request (`bearer` vs `mtls`) — useful during migration windows.
- Worked deployment example: issuing certificates from a small internal CA (smallstep, easy-rsa, or step-ca).
- `both` mode allows incremental migration: high-value agents get certs first, others stay on bearer, with operator visibility into which is which.

**Out of scope:**
- Locksmith acting as its own CA (use external CA — smallstep, internal PKI, etc.).
- SPIFFE / workload identity (could be a future milestone if customer pull justifies it).

**Acceptance:** UC-12 demonstrable. `bearer`, `mtls`, and `both` modes all work. Operator API also supports mTLS. Migration path documented.

**Dependencies:** M2 (pluggable authenticator trait), M4 (admin API to harden), M5 (at-rest hardening, so the strongest authentication isn't fronting weakly-protected secrets).

**Requirements satisfied:** R-F16.

#### M7 — Response-side controls

**Goal:** Application-layer controls on what comes back from upstream, complementary to Pipelock's network-layer DLP.

**In scope (intent and constraints):**
- Per-tool maximum response size (with sensible default; configurable).
- Per-tool content-type allowlist (e.g., GitHub returns `application/json`; reject `text/html` if the upstream is misbehaving or compromised).
- Per-tool optional regex-based response redaction (not a full DLP — covers obvious cases like accidental key echo).
- Constraint: streaming responses (M1) must not be broken by these controls; size and redaction apply to non-streaming responses, with streaming responses subject only to total-size cap if configured.

**Out of scope:**
- Schema validation of response bodies.
- Content scanning beyond regex (defer to LlamaFirewall or similar).

**Acceptance:** Operator can configure a tool to reject responses >10MB, only `application/json`, and redact strings matching a configured pattern. Existing streaming flows unaffected.

**Dependencies:** M2 (per-agent context for audit of redactions), M3 (audit redaction events).

**Requirements satisfied:** R-F15.

## 12. Assumptions and dependencies

Locksmith's design assumes that the surrounding ecosystem provides several capabilities. The product composes with these as peers; it does not rebuild them.

### 12.1 Assumed peers

- **Pipelock (or equivalent network egress controller).** When `egress: proxied` is configured for a tool, Locksmith forwards the request through an HTTP CONNECT proxy. Pipelock is the canonical implementation of that proxy in the openclaw-hardened deployment, but any HTTP CONNECT proxy is supported. Locksmith does not implement domain allowlisting, DLP, or SSRF protection itself.
- **LlamaFirewall (or equivalent cognitive scanner).** Cognitive scanning runs in-process inside the agent, not on the wire. Locksmith does not integrate with, front, or special-case cognitive scanners. The agent imports its scanner library and uses it according to that library's design; Locksmith handles outbound HTTP independently. Both run in parallel inside a hardened deployment, neither in the other's path.
- **Inference platform (Kamiwaza for enterprise, LiteLLM proxy or similar for those who run one, or direct-to-provider).** Provider routing, fallback, retry, and budget logic live in the inference platform. Locksmith treats inference endpoints — whether a cloud provider or a dispatching proxy — as ordinary tool entries.
- **Secret backend (in M5+).** Environment variables are the default backend. Sealed-secret files (decrypted via `systemd-creds` or equivalent) are the M5 deliverable. Vault and AWS Secrets Manager arrive as future backends conforming to the M5 trait without core changes.
- **External CA (in M6).** Locksmith does not act as its own CA. mTLS deployments rely on an external CA (smallstep, step-ca, easy-rsa, internal PKI).

### 12.2 Operational assumptions

- Operators have shell access to the host running Locksmith (Unix socket admin in v1 through M3; HTTPS admin from M4 onward).
- Operators manage configuration via GitOps for tools and infrastructure (YAML) and via CLI/admin API for mutable state (agents, bootstrap tokens, audit). The split is intentional (D-2).
- Operators maintain backups via `locksmith export` (M3) for agent state and standard SQLite backup tooling for the database.
- Agents are HTTP-speaking. No SDK is required (R-N8). Locksmith does not provide a client library and does not need one.

### 12.3 Repository layout

The repo migrates to a v1/v2 split for documentation:

```
docs/
  v1/
    SPEC.md           ← moved from repo root
    plans/
      [previous M1–M4 roadmap docs]
  v2/
    roadmap.md        ← source roadmap
    PRD.md            ← this document
    SPEC.md           ← detailed design, produced from this PRD
    decisions.md      ← see §15 (architectural decisions)
```

Top-level `README.md` references the v2 docs as canonical and the v1 docs as historical. Code in `src/` continues to evolve forward — the v1/v2 split is for docs only, not for code.

## 13. Out of scope

Beyond the per-milestone "out of scope" sections in §11, the following are explicit non-goals for v2 (drawn from roadmap §5 "Deferred / Out of Scope"):

- **MCP bridging.** Wait for a real use case. Locksmith's existing path-based proxy already covers credential-injection-for-HTTP-services. If MCP becomes dominant, future work might be Locksmith *as* an MCP server, not a bridge.
- **Agent-to-agent (A2A) forwarding.** Different threat model. Agents authenticating to agents is meaningfully different from agents authenticating to upstream APIs. Possibly a sibling project.
- **Inference routing, fallbacks, budgets, rate limiting.** Inference platform territory (Kamiwaza for enterprise, LiteLLM proxy or similar for those who run one). Locksmith proxies to whichever inference endpoint exists and does not implement gateway features.
- **Per-model routing or model-aware policy.** Locksmith does not inspect request payloads (R-F18, D-11). If destination policy needs to vary by model, configure separate tool entries per destination class.
- **Cloud sync of agent state across deployments.** Solved by Ansible / GitOps for the audiences Locksmith targets. Re-solving would add a sync layer and a cloud service that doesn't fit the single-binary model.
- **Web UI.** Genuinely useful, but the CLI and HTTP API cover capability. UI is a usability layer that can lag and possibly live as a sibling project.
- **Operator role granularity.** v1 operator credentials are all-or-nothing. The schema reserves a `scope` field for future use; expose only when there's a customer asking.
- **Real-time audit streaming.** Defer to operator's log shipping infrastructure; M3 ships an optional JSONL secondary sink that integrates with that.
- **Audit log signing / tamper-evidence.** Could be a future milestone if a customer asks.
- **Schema validation of response bodies.** Out of scope for M7 response controls.
- **Content scanning beyond regex redaction.** Defer to LlamaFirewall or similar.
- **HSM integration, SPIFFE / workload identity, Locksmith-as-CA.** All deferred; external CA is sufficient for M6.

## 14. Risks and resolved decisions

Risks remain on the table for ongoing mitigation. The ambiguities surfaced during PRD formalization have been resolved and are recorded below as binding decisions for downstream design.

### 14.1 Resolved decisions

These are the resolutions of the questions surfaced during PRD formalization. They bind downstream design unless explicitly re-litigated.

1. **Calendar estimates live in a separate planning artifact.** Calendar and team-size estimates are not committed in this PRD. Indicative ranges and T-shirt sizes for M1–M7 live in `docs/v2/PLAN.md` (to be produced) so the PRD can stay clean while the plan can be re-baselined freely.
2. **CI strategy for cloud-provider integration tests: local-only.** Cloud-provider integration tests (Anthropic, OpenAI, Kamiwaza) run only on engineer workstations with credentials supplied via local env vars. Default CI runs the local-upstream lane only (test fixtures, Ollama if present, LM Studio if present). Engineers run the cloud-provider matrix pre-PR. No credentialed CI lane in v2.
3. **Bootstrap token transport in high-security deployments: bootstrap-only listener.** Locksmith exposes a separate, narrowly-scoped listener that performs server-TLS but does not require client mTLS, accepting only the `register` endpoint with a bootstrap token. Locked down by network policy (Tailscale, localhost-only, etc.) and turned off when not onboarding. The out-of-band cert-issuance pattern (operator issues bootstrap token *and* client cert via internal CA, agent presents both at first contact) is documented as the enterprise variant but not built as a Locksmith feature.
4. **Operator credentials: per-operator named tokens, argon2-hashed in file.** Operator credentials are an array of records in operator-only configuration: `operators: [{name: alice, token_hash: argon2:..., scope: null}]`. Cleartext lives in each operator's password manager; only hashes are at rest. Rotation = mint a new token for one operator without disturbing others. Same argon2 parameters as agent tokens, for consistency. The reserved `scope` field (D-6) attaches here.
5. **Migration tool: `sqlx` with `sqlx::migrate!`.** `sqlx` is the single SQL dependency for both query layer (compile-time-checked queries via `query!`/`query_as!`) and migrations (SQL files embedded at compile time). Decision binding for M2 onward; do not introduce `rusqlite` or `refinery`.
6. **Audit JSONL secondary sink: mirror SQLite columns, drop-newest back-pressure.** When configured, the JSONL sink emits one record per audit event with the same field names as the SQLite columns (`ts`, `agent_id`, `tool`, `upstream_host`, `method`, `path`, `status`, `latency_ms`, `decision`) plus a stable `schema_version` field. Rotation: daily file with size-based 100MB cap, named `audit-YYYYMMDD.jsonl`. Back-pressure: bounded channel (default 10k entries) with drop-newest policy and an `audit_jsonl_dropped_total` counter; SQLite remains the system of record.
7. **Audit retention default: 90 days, time-based.** Default retention is a 90-day rolling window (time-based form). A `--retention-max-rows` configurable cap is also enforced as a safety net for runaway-traffic scenarios. Both are configurable per deployment; enterprise deployments can extend.
8. **Bootstrap token reuse attempt: 401 + `invalid_credential`, audited as security event.** Reuse of a consumed or revoked bootstrap token returns `401 Unauthorized` with a structured body `{"error": "invalid_credential"}` — the response does not distinguish "wrong" from "used" to avoid leaking token-state to attackers. The attempt is recorded in the audit log as a `bootstrap_reuse_attempt` event with the hashed token id and source IP, increments a metric counter, and is eligible for an operator-visible alert when configured.
9. **Rotation grace window: revisit post-M3 from data.** D-13's "no grace window in v1" stands. The revisit trigger is a post-M3 data review: query "for each `rotate` event, the next 60 seconds of 401 events from that agent." If the distribution shows real operational pain, a configurable grace window is added in M5 or later. Tracked as a deferred review item, not a blocker.
10. **mTLS revocation: CRL plus local emergency blocklist.** M6 ships both a CRL fetcher (periodic, configurable interval, fed from the operator's existing CA workflow) and a Locksmith-local blocklist of revoked certificate serials managed via `locksmith mtls revoke <serial>`. CRL provides the sustainable workflow; the local blocklist gives operators an emergency lever that does not wait on a CA refresh. OCSP is not implemented (operationally heavy and couples Locksmith availability to CA availability).
11. **`auth_mode` requires restart; R-N5 carve-out.** `auth_mode`, listener port, and TLS certificate paths are listener-shape changes that require a restart to rebind. R-N5 has been updated to reflect this exception. All other config and database changes remain hot-reloadable.
12. **Secret backend resolution strategy: backend-specific contract.** Each `SecretBackend` advertises its resolution strategy. M5 ships only env-variable and file-sealed backends, both startup-resolved and cached in memory (zeroized on shutdown). Future Vault and AWS Secrets Manager backends are permitted to resolve lazily with a TTL cache to support upstream-credential rotation without restart. Per-tool `egress` and per-tool secret backend remain independent axes; no special-case interaction in v1.

### 14.2 Risks

- **Scope creep into LLM gateway territory.** The pull to add provider routing, fallbacks, or model-aware policy will be persistent (D-11, D-15, D-17 exist precisely because the temptation is real). Mitigation: keep the "What Locksmith is not" framing prominent and route every "shouldn't Locksmith do X" question through the decisions appendix.
- **Schema regret in M2.** M2 is the load-bearing milestone. Schema choices compound into M3–M7. Mitigation: kickoff prompt requires sketching the schema in `docs/v2/SPEC.md` before any M2 code, with explicit review gate.
- **Streaming-passthrough subtleties.** SSE first-byte latency under 100ms is a strict gate. Buffering can creep in via TLS termination, body decompression, or hyperscaler proxies. Mitigation: M1 begins with a failing integration test for streaming timing, not with an implementation.
- **mTLS migration friction.** Operators with large agent fleets will not migrate atomically. `auth_mode: both` (D-8) is the mitigation, but the user experience of the migration window (per-agent visibility, audit attribution, partial-rollback) is not fully specified.
- **Adjacent-tool drift.** Locksmith's composability story depends on Pipelock, LlamaFirewall, and inference platforms staying in their lanes too. If an adjacent tool absorbs credential injection or per-agent identity, Locksmith's positioning is challenged. Mitigation: D-18 corollary ("composed middleware does not duplicate Locksmith's responsibilities") provides the contract; documentation should reinforce it.
- **Homelab vs enterprise feature pull.** The same-product positioning relies on the enterprise feature set (mTLS, audit retention, sealed secrets) not making the homelab experience heavier. Mitigation: every advanced feature is opt-in (mTLS off by default, admin HTTP off by default, sealed secrets behind a backend flag).

## 15. Architectural decisions (appendix)

This appendix preserves the architectural decisions that produced this roadmap, with their reasoning. Detailed design treats these as settled unless a new constraint forces re-litigation. Decisions are referenced by ID throughout the PRD.

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

**Operator option:** If a deployment wants uniform egress policy (e.g., "every agent call subject to a single allowlist regardless of destination"), the per-tool `egress: proxied` flag supports this — set every tool to `proxied` and configure Pipelock with explicit LAN allowances. The tradeoff is documented in roadmap §9.3: Pipelock's SSRF protection becomes an allowlist rather than default-deny, and local inference incurs proxy overhead for limited audit benefit.

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
