# Agent Locksmith v2 — System Design Working Document

**Status:** Draft
**Version:** 0.1.0
**Date:** 2026-04-28
**Project:** Agent Locksmith — credential and identity substrate for AI agents
**Source PRD:** `docs/v2/PRD.md`
**Authors:** John Stanford

---

## 1. Introduction

This document is the detailed design for Agent Locksmith v2. It is produced from the formalized PRD in `docs/v2/PRD.md` via the SoftwareDesign / CreateDesign workflow. Where the PRD answers *what* and *why*, this document answers *how* — the components, layers, interfaces, sequences, data model, and milestone-level execution plan that deliver the PRD's seven milestones (M1–M7) against its requirements.

The PRD's identifier scheme is preserved verbatim. Use cases (`UC-1`..`UC-13`), functional requirements (`R-F1`..`R-F18`), non-functional requirements (`R-N1`..`R-N10`), milestones (`M1`..`M7`), and architectural decisions (`D-1`..`D-18`) are referenced throughout. Design-derived additions are introduced under prefixes that do not collide with the PRD's namespace: `INF-N` for requirements inferred during design, `Q-N` for open questions raised during design, `C-N` for components, and `T<milestone>.<N>` for implementation tasks.

The design treats the 12 resolved decisions in PRD §14.1 as binding — they answer questions the PRD surfaced during formalization, and this document encodes them at implementation depth (schema choices, file layouts, listener-binding behavior, retention defaults, response-shape choices).

### 1.1 Source Projects

| # | Project | Status | Estimate |
|---|---------|--------|----------|
| 1 | Agent Locksmith v2 (M1–M7) | Active | See §6 milestone breakdown |

### 1.2 Related Projects

| Project | Relevance |
|---------|-----------|
| Pipelock | Network egress controller; composes with Locksmith per D-16 |
| LlamaFirewall (and similar cognitive scanners) | In-process scanning library; composes per D-18 |
| Kamiwaza inference platform | One inference upstream among many; D-11, D-17 keep Locksmith provider-agnostic |
| openclaw-hardened | Proving-ground deployment; consumes Locksmith via Ansible |
| LiteLLM proxy / vLLM / TGI | OpenAI-compatible inference proxies; treated as ordinary tool entries |

### 1.3 Reformulation Summary

No structural changes to the PRD's UC/requirement/milestone organization are recommended. The PRD's seven-milestone breakdown (M1 inference-ready hardening → M7 response-side controls) is internally consistent, customer-traceable, and dependency-correct. The design document organizes its workstreams to match (Appendix A).

The PRD is deeper than typical product specifications — its decisions appendix (D-1..D-18) and resolved-decisions section (§14.1) carry many of the architectural choices a design phase would otherwise produce. The remaining design surface for this document is therefore:

1. The data model and schema details deferred to "design phase" by PRD §M2 (now covered in §4.6 of this document).
2. The component decomposition implied by the PRD but not enumerated (now §4.2).
3. The systemic interfaces to external infrastructure (logging, metrics, TLS, secret backends, CRL distribution) that the PRD references but does not specify (§4.4).
4. The interaction sequences for the load-bearing flows (registration via bootstrap, rotation, streaming proxy, mTLS handshake, audit query) (§4.5).
5. The implementation plan that turns each milestone into ordered tasks (§6).

---

## 2. Open Questions & Assumptions

Open questions surfaced during the design phases (1–4). Items inherited from the PRD's §14.1 resolved decisions are listed with status `Resolved (PRD §14.1 #N)` for traceability — they are not re-litigated here. Design-phase additions begin at `Q-13`.

| # | Item | Source | Status |
|---|------|--------|--------|
| Q-1 | Calendar estimates and team-size commitments | PRD §14.1 #1 | Resolved — separate `docs/v2/PLAN.md` artifact |
| Q-2 | CI strategy for cloud-provider integration tests | PRD §14.1 #2 | Resolved — local-only; cloud tests run on engineer workstations pre-PR |
| Q-3 | Bootstrap token transport in mtls-only deployments | PRD §14.1 #3 | Resolved — bootstrap-only listener pattern |
| Q-4 | Operator credential format and rotation | PRD §14.1 #4 | Resolved — per-operator named tokens, argon2-hashed in file |
| Q-5 | SQLite migration tool choice | PRD §14.1 #5 | Resolved — `sqlx::migrate!` with `sqlx` for queries |
| Q-6 | Audit JSONL sink schema and back-pressure | PRD §14.1 #6 | Resolved — mirror SQLite columns; bounded channel + drop-newest |
| Q-7 | Audit retention default | PRD §14.1 #7 | Resolved — 90 days, time-based, with row-count safety cap |
| Q-8 | Bootstrap token reuse-attempt response | PRD §14.1 #8 | Resolved — 401 + `invalid_credential`; audited as security event |
| Q-9 | Rotation grace-window threshold | PRD §14.1 #9 | Resolved — defer to post-M3 data review |
| Q-10 | mTLS revocation list mechanism | PRD §14.1 #10 | Resolved — CRL fetcher + local emergency blocklist |
| Q-11 | `auth_mode` runtime change semantics | PRD §14.1 #11 | Resolved — listener-shape changes require restart (R-N5 carve-out) |
| Q-12 | Per-tool `egress` × per-tool secret backend interaction | PRD §14.1 #12 | Resolved — backend-specific resolution contract; M5 ships startup-only |
| Q-13 | argon2 parameter choice for token hashing | Phase 1 inference | Resolved — argon2id, m=4 MiB, t=3, p=1 (~5ms/verify); configurable per deployment; defense-in-depth above 256-bit token entropy |
| Q-14 | Constant-time bearer-token comparison scope | Phase 1 inference (R-N4 corollary) | Resolved — structured tokens `lk_<public-id>.<secret>`: lookup by public id (non-secret), constant-time verify the secret half via argon2 |
| Q-15 | Rate limiting on `register`, `rotate`, and operator endpoints | Phase 1 inference | Resolved — `register`: per-IP token bucket (60 req/min default). `rotate` and operator endpoints: per-IP + per-target-id (10 failed verifies / 5 min). 429 + `Retry-After` on overflow; audit event written; in-memory (single-instance) |
| Q-16 | SQLite journal mode | Phase 1 inference | Resolved — `journal_mode=WAL`, `synchronous=NORMAL`, `wal_autocheckpoint=1000`. `locksmith maintenance` exposes manual `wal_checkpoint(TRUNCATE)` |
| Q-17 | Secret-backend startup failure behavior | Phase 1 inference | Resolved — global `secret_backend_failure: fail-fast` (default) with per-tool `on_secret_failure: degraded` override; degraded tools surface as unavailable in `GET /tools` and `503` on direct calls |
| Q-18 | Health-check endpoint scope | Phase 1 inference | Resolved — k8s-style split: `/livez` (process up), `/readyz` (DB reachable + listener bound + required backends resolved), `/version`. All on the agent listener, unauthenticated |
| Q-19 | Metrics surface | Phase 1 inference | Resolved — Prometheus text exposition on a separate listener port, off-by-default. OTel export deferred |
| Q-20 | Concurrent rotation by the same agent | Phase 1 inference | Resolved — first-committer wins, second returns `409 Conflict` + `{"error": "rotation_in_progress"}` (INF-9 stands as proposed) |
| Q-21 | JSONL audit sink unreachable at startup | Phase 1 inference | Resolved — default: start with sink disabled, warning logged, `audit_jsonl_disabled` metric increments. Opt-in `audit.jsonl_required: true` to refuse-to-start |
| Q-22 | Streaming-response concurrency cap | Phase 1 inference | Resolved — per-agent default cap 50 + global default cap 1000, whichever is hit first; both configurable; both surface as metrics |
| Q-23 | Operator-action vs proxied-call audit retention | Phase 1 inference | Resolved — two retention windows: `audit.proxy_retention_days` (default 90), `audit.operator_retention_days` (default 365); driven by `event_class` column on each row |
| Q-24 | Admin Unix socket permissions and ownership | Phase 1 inference | Resolved — mode 0660, owner `locksmith` user, group `locksmith` (configurable). Operator-credential check enforced *over* the socket as a second layer (defense-in-depth) |
| Q-25 | M0 dead-code `TelemetryConfig` cleanup policy | Phase 2 codebase analysis | Resolved — delete the struct; introduce a generalized "deprecated/removed fields" tolerance mechanism that one-shot-warns on encounter (covers `telemetry`, the M0 `cloud:` rename, and any future removed fields under one mechanism) |
| Q-26 | Textual `${VAR}` expansion fragility | Phase 2 codebase analysis | Resolved (option C) — pre-parse textual expansion is removed (it silently corrupts on YAML-significant chars); replaced by field-scoped `${VAR}` expansion on string-shaped secret fields (back-compat for the dominant case, deprecation-warned via INF-24) **plus** a typed `SecretRef` form (`{ from_env: ..., from_file_sealed: ... }`) for new deployments and future M5 backends. v3 will remove the deprecated string form. See INF-23 |
| Q-27 | Per-tool reqwest client pooling key | Phase 2 codebase analysis | Resolved — pool per `tool_name`; client lazily constructed on first use; evicted on YAML hot-reload of the affected tool entry |
| Q-28 | M3 audit-write path: synchronous vs async-batched | Phase 3 design (R-4 risk) | Resolved — synchronous SQLite insert per request is the v2 default. M3 ships a benchmark task that measures audit-write latency at 10/100/1000 sustained req/s on commodity SSD; if the benchmark shows added proxy-hot-path latency >5ms (95th percentile) *or* sustained `audit_write_queue_depth > 0`, fall back to bounded async-batched (mpsc channel, batched INSERTs every 100 rows or 100ms, SQLite still canonical). Metric `audit_write_queue_depth` exposes the trigger condition operationally. See INF-26 for scale envelope |

### 2.1 Assumptions requiring validation at deployment time

These are sizing or hardware assumptions that the design treats as fixed but that depend on operator-controlled environment. They are not open questions in the design sense — the design choice is locked — but they identify validation points where a deployment outside the assumed band may need to retune defaults.

| # | Assumption | Where it shows up | How operator validates / retunes |
|---|------------|-------------------|----------------------------------|
| A-1 | argon2id verify cost is ~5ms on commodity hardware (Q-13). Older ARM SBCs or shared-CPU VMs may be 15–20ms, compounding with per-request auth | INF-5 (token verification on every request) | Run `locksmith bench auth` at deploy time (M2 task); if verify >10ms, lower `m` parameter or accept the latency. argon2 parameters are configurable per deployment per Q-13 resolution |
| A-2 | SQLite WAL-mode write throughput sits at 5–20k single-row INSERT/sec on commodity SSD; v2 envelope of 1000 sustained writes/sec assumes this band (INF-26) | INF-26 scale envelope; Q-28 audit-write strategy | Operators on slower disks (network-mounted, spinning rust, constrained k8s persistent volumes) should run the M3 audit-write benchmark to verify they sit inside their actual envelope |
| A-3 | Default streaming concurrency caps (per-agent 50, global 1000) are sized for Linux default fd limits (1024) or raised limits (65535). Constrained k8s pod fd limits or BSD-style descriptor accounting may require lowering | INF-18 / Q-22 streaming caps | Both caps are configurable; the `streaming_concurrency_high_water_mark` metric (M3+) shows actual peak utilization for tuning |
| A-4 | "Required secret backend" for `/readyz` (INF-3) means "any tool that has not opted into per-tool `on_secret_failure: degraded`". Under global `secret_backend_failure: degraded` mode, no backends are required — `/readyz` reduces to DB-reachable + listener-bound. Operators choosing global `degraded` are explicitly opting out of credential-resolution-as-readiness | INF-3, INF-4 / Q-17, Q-18 | If a globally-degraded deployment wants "at least one operational tool" as a readiness floor, that's a future enhancement; currently not built |

---

## 3. Existing Foundation

This section captures the M0 implementation as it stands at commit `f826694` on branch `main`. It is the substrate the v2 milestones modify and extend. Where M2+ introduces concepts the M0 codebase has no counterpart for (persistence, identity, admin protocol), Section 3 records *absence* explicitly so design changes in §4 are traceable to the gap they fill.

### 3.1 Codebase Snapshot

| Repository | Branch | Commit | Date | Relevant Paths |
|-----------|--------|--------|------|---------------|
| `/Users/jxstanford/devel/sentientswarm/agent-locksmith` | `main` | `f826694` | 2026-03-14 | `src/`, `tests/`, `Cargo.toml`, `config.example.yaml` |

The M0 implementation is small and tractable: 452 lines across 7 source modules, 8 integration test files. The compactness is deliberate — M0 ships a single-purpose proxy and nothing more.

### 3.2 Module Map (M0)

| Module | Lines | Purpose |
|--------|-------|---------|
| `src/main.rs` | 61 | Process entrypoint: parse CLI, load config, init logging, bind listener, install ctrl-c handler, serve |
| `src/lib.rs` | 5 | Re-exports the four feature modules so integration tests can build a router via `app::build_app` |
| `src/app.rs` | 70 | Router assembly. Holds `AppState { config: ArcSwap<AppConfig>, started_at: Instant }`. Three routes: `GET /health`, `GET /tools`, `ANY /api/{tool}/{*path}`. Auth middleware applied process-wide (with `/health` carve-out inside the middleware) |
| `src/auth.rs` | 50 | Inbound auth middleware. Bearer-token comparison via `secrecy::ExposeSecret` + Rust `==` (not constant-time) |
| `src/config.rs` | 122 | Config types and YAML loader. Supports `${VAR}` env-var expansion *over the raw YAML text* before parse |
| `src/proxy.rs` | 130 | The proxy handler. Looks up the tool by name, forwards method+headers+body to upstream, strips inbound auth headers, injects per-tool credential, returns response. `cloud: true` tools route via configured `egress_proxy` URL |
| `src/telemetry.rs` | 14 | `tracing-subscriber` setup with JSON layer and `EnvFilter` |

### 3.3 Layered Architecture (M0)

The current architecture has three layers, all in-process:

```
┌─────────────────────────────────────────────────────────────┐
│  Listener / HTTP framing                                    │
│  axum 0.8 + hyper 1 + tokio                                 │
│  src/main.rs (TcpListener::bind, axum::serve)               │
└─────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────┐
│  Routing / Middleware                                       │
│  axum::Router + tower-http TraceLayer                       │
│  src/app.rs (build_app)                                     │
│    ├─ TraceLayer (request tracing)                          │
│    └─ auth_middleware (Bearer-token gate; bypasses /health) │
└─────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────┐
│  Handlers                                                   │
│  src/app.rs::health_handler, tools_handler                  │
│  src/proxy.rs::proxy_handler (reqwest client to upstream)   │
└─────────────────────────────────────────────────────────────┘
```

| Layer | Owns | Database | M2+ Awareness |
|-------|------|----------|---------------|
| **Listener** | TCP bind, signal handling, graceful shutdown wiring | none | None — single agent listener; M2 adds Unix admin socket; M4 adds HTTPS admin listener |
| **Routing/Middleware** | URL-to-handler dispatch, auth gate, request tracing | none | None — auth is single-token static; M2 introduces per-agent auth via `AgentAuthenticator` trait |
| **Handlers** | Health probe, tool discovery, proxy forwarding | none | None — handlers consume `AppState` directly; M2 introduces per-handler service traits backed by SQLite |

### 3.4 Current Configuration Surface (`AppConfig`)

The configuration is wholly YAML; nothing is persisted by the daemon. Verbatim shape from `src/config.rs`:

```yaml
listen:
  host: "127.0.0.1"        # default 127.0.0.1
  port: 9200               # default 9200

inbound_auth:              # optional; absence = no auth required
  mode: "bearer"
  token: "${SAP_INBOUND_TOKEN}"

egress_proxy: "http://..." # optional; HTTP CONNECT proxy URL

telemetry:                 # optional; not currently wired to anything
  enabled: false
  otlp_endpoint: "..."
  service_name: "..."

logging:
  level: "info"            # default "info"
  file: "..."              # optional; not currently used

tools:                     # default empty
  - name: "github"
    description: "..."
    upstream: "https://api.github.com"
    cloud: true            # ← becomes egress: proxied|direct in M1 (R-F13, INF-15)
    auth:
      header: "Authorization"
      value: "Bearer ${GITHUB_TOKEN}"
    timeout_seconds: 30    # default 30
```

**Observations relevant to M2+:**

- The struct uses `serde` defaults but does not use `deny_unknown_fields`, so unknown fields are silently ignored. INF-17 requires this be tightened.
- `${VAR}` expansion is **textual, applied to the raw YAML before parse**. This means it works for any field type but breaks if the env var contains characters that need YAML escaping (e.g., `:`, leading whitespace, `null`). The pattern works for tokens and URLs in practice but is a footgun.
- Missing env vars expand to *empty string*, not error. `active_tools()` then filters out tools whose `auth.value` is empty — meaning a missing credential silently disables a tool with no operator notification. INF-4 / Q-17 resolution (configurable startup behavior) directly addresses this.
- There is no `egress` field. The `cloud: bool` field is the M0 ancestor; M1 (per R-F13 + PRD §M1) renames to `egress: direct | proxied` with a backward-compat shim.

### 3.5 Current API Surface (M0)

| Method | Endpoint | Operation | Auth |
|--------|----------|-----------|------|
| `GET` | `/health` | Returns `{ status, uptime_seconds, tools, version }`. **Bypasses auth** | None |
| `GET` | `/tools` | Returns `{ tools: [{ name, type: "api", path, description }] }` for active tools | Inbound bearer if configured |
| `ANY` | `/api/{tool_name}/{*path}` | Proxy to `upstream/{*path}` with credential injection | Inbound bearer if configured |

There is no admin surface. There is no per-agent identity. The single inbound bearer token (if configured) is the only auth.

### 3.6 Current Auth Model (M0)

`auth_middleware` (auth.rs):

1. If `req.uri().path() == "/health"` → bypass.
2. If `inbound_auth` is `None` *or* `mode != "bearer"` *or* no token configured → bypass.
3. Otherwise: extract `Authorization: Bearer <token>` from request, compare to `expected_token.expose_secret()` with Rust `==`.

Gaps versus PRD requirements:

| Gap | Source requirement | Resolved by |
|-----|-------------------|-------------|
| Comparison is not constant-time | INF-5 / R-N4 (R-N4 corollary) | M2 introduces structured tokens + argon2-verify |
| Single static token shared by all callers | R-F3 (per-agent identity) | M2 |
| Token in plaintext in process memory beyond config load | R-N3 (zeroize on drop) | The wrapper is `secrecy::SecretString`, so this is *partially* satisfied; argon2 hashing under M2 reduces the in-memory cleartext surface further |
| `/health` carve-out is hardcoded inside middleware logic | (no explicit gap, but a smell) | M2 splits middleware along listener boundary so the agent listener is fully gated and admin listener is gated by its own credentials |
| `mode != "bearer"` silently disables auth | INF-17 | M2 (parsing rejects unknown values) |

### 3.7 Current Proxy Behavior (M0)

`proxy_handler` (proxy.rs):

1. Find the tool by name in `active_tools()`. Return 404 if not found.
2. Read the entire request body into memory with a 10 MiB cap (`axum::body::to_bytes(body, 10 * 1024 * 1024)`).
3. Build a `reqwest::Client` per-request: timeout from `tool.timeout_seconds`, optional egress proxy if `tool.cloud` and `egress_proxy` configured.
4. Forward method + headers (stripping `host`, `authorization`, `x-api-key`, and the configured tool auth header) + body to `tool.upstream/{*path}`.
5. Inject the configured `auth.header: auth.value` on the upstream request.
6. **Read the entire upstream response body into memory** with `resp.bytes().await`, then return it.

**Critical observation: streaming is not implemented.** Step 6 buffers the full response before returning it to the agent. Server-sent events, long inference responses, and any response larger than the implicit memory budget either delay the client by the full response time or fail. This is the M1 gap; R-N6 (≤100ms first-byte added latency) is currently unsatisfiable. The fix is to switch from `resp.bytes().await` to a `reqwest::Response::bytes_stream()` piped into an `axum::body::Body::from_stream(...)`.

**Other M0 proxy gaps versus PRD requirements:**

| Gap | Source | Resolved by |
|-----|--------|-------------|
| Body size cap is hardcoded at 10 MiB | R-F12 (per-tool body limits) | M1 |
| No request timeout distinct from total timeout | R-F12 | M1 |
| No per-tool response-size limit, content-type allowlist, or redaction | R-F15 | M7 |
| `cloud:` field name | R-F13 | M1 (rename + shim) |
| No audit logging of proxied requests | R-F7 | M3 |
| Client built per-request (no connection pooling across calls) | implicit perf concern | not strictly addressed by PRD; design will pool clients per-tool in §4 |

### 3.8 Current Observability Surface

| Capability | Current state | Source files |
|------------|---------------|--------------|
| Structured logs | `tracing` + `tracing-subscriber` JSON layer; `EnvFilter` for level | `src/telemetry.rs`, used in `src/main.rs` |
| Request tracing | `tower_http::trace::TraceLayer` applied in `app.rs` | `src/app.rs` |
| Metrics | None | — |
| Distributed tracing (OTel) | `TelemetryConfig` struct exists with `otlp_endpoint` / `service_name` fields, but **the struct is not wired to any subscriber layer** (dead config) | `src/config.rs` |
| Health endpoint | `/health` returns liveness + uptime + tools list + version | `src/app.rs::health_handler` |

The `TelemetryConfig` dead-code struct should be removed or wired in M1 cleanup; INF-19 / Q-19 resolution adds Prometheus metrics on a separate listener, which is the v2 metrics path.

### 3.9 Current Test Surface

8 integration test files in `tests/`, exercising:

| Test | Scope |
|------|-------|
| `auth_test.rs` | Inbound bearer-token enforcement, /health bypass |
| `config_test.rs` | YAML parsing, defaults, env var expansion of secret fields |
| `discovery_test.rs` | `/tools` filters out unconfigured tools |
| `env_expansion_test.rs` | `${VAR}` substitution edge cases |
| `health_test.rs` | `/health` shape and content |
| `integration_test.rs` | End-to-end router smoke |
| `proxy_test.rs` | Forward to a `wiremock` upstream, header stripping, credential injection |
| `tool_activation_test.rs` | Active-tools filtering when credential env var is empty |

`wiremock` is the upstream-mock dependency. None of the existing tests exercise SSE/streaming — the M1 first failing test (per PRD §kickoff "Suggested order of attack") is the streaming integration test that does not yet exist.

### 3.10 Current Dependency Inventory (Cargo.toml)

| Dependency | Version | Role |
|-----------|---------|------|
| `axum` | 0.8 | HTTP server framework |
| `hyper` | 1 (full) | Lower-level HTTP, used transitively by axum |
| `tokio` | 1 (full) | Async runtime |
| `tower` | 0.5 | Service abstraction |
| `tower-http` | 0.6 (trace, cors) | Middleware: request tracing + CORS |
| `reqwest` | 0.12 (json, stream, rustls-tls) | Upstream HTTP client. Note `stream` and `rustls-tls` features already enabled; M1 just needs to *use* them |
| `clap` | 4 (derive) | CLI parsing |
| `arc-swap` | 1 | Lock-free `AppConfig` swap (R-N5 hot reload primitive) |
| `secrecy` | 0.10 (serde) | `SecretString` for credential values (R-N3) |
| `serde`, `serde_json`, `serde_yaml` | — | Serialization |
| `tracing`, `tracing-subscriber` | 0.1, 0.3 (json, env-filter) | Logging |
| `http-body-util` | 0.1 | Body construction utilities |
| `wiremock` (dev) | 0.6 | Upstream mock for tests |
| `axum-test` | 19 (dev) | High-level integration test client |

**Dependencies needed for M2+ that are not yet present:**

| Crate | Milestone | Purpose |
|-------|-----------|---------|
| `sqlx` (with `sqlite`, `runtime-tokio-rustls`, `migrate` features) | M2 | DB access + migrations (Q-5 resolution) |
| `argon2` (or `rust-argon2`) | M2 | Token hashing (R-N2, INF-5) |
| `rand` + `getrandom` | M2 | Cryptographic random for token generation |
| `hyper-util` or `tower::Service` for Unix socket | M2 | Admin Unix socket binding |
| `prometheus` or `metrics` + `metrics-exporter-prometheus` | M3+ (off-by-default) | Metrics exposition (INF-14) |
| `rustls-pemfile`, `rcgen` (dev) | M4, M6 | TLS cert loading + test cert minting |
| `x509-parser` or similar | M6 | Certificate identity extraction (R-F16) |
| `serde_yaml` already present | M3 | Used for `locksmith export agents --format yaml` (R-F14) |

### 3.11 Architectural Decisions Inherited from M0

These are not PRD §15 decisions; they are *de facto* architectural choices the M0 codebase has made that v2 inherits or revisits.

**M0-A1: ArcSwap for hot-reloadable config.** `AppConfig` is held as `ArcSwap<AppConfig>` in `AppState`, so handlers do `state.config.load()` to get a snapshot. R-N5's hot-reload assurance leans directly on this primitive. M2 keeps it; database-backed state uses `sqlx::Pool` separately.

**M0-A2: Process-wide auth middleware with path carve-out.** The current single auth middleware checks the path inside its body to bypass `/health`. M2's design moves toward listener-boundary separation: the agent listener has agent-auth middleware (always on); the admin Unix socket has operator-auth middleware (always on); the admin HTTPS listener (M4) has both depending on namespace. Path-based bypasses are an antipattern at scale.

**M0-A3: Per-request reqwest client construction.** Each call to `proxy_handler` builds a fresh `reqwest::Client` from `build_client(tool, &config)`. This works but loses connection pooling. v2 design pools clients per-tool, keyed on `(tool_name, egress)` so connection state survives across calls.

**M0-A4: Textual env-var expansion in config loader.** The `expand_env_vars` function operates on raw YAML text before parsing. v2 keeps this for backward compatibility with M0 deployments but the secret-backend abstraction (M5, R-F17) layers on top — env-var resolution becomes one `SecretBackend` implementation rather than a textual preprocessor for everything.

**M0-A5: No persistence; everything from YAML.** M2 introduces SQLite for agents/tokens/audit but **preserves the YAML-as-source-of-truth model for tools and infrastructure** (R-F8, D-2). The split is clean: tools/listeners/egress in YAML; agents/tokens/audit in SQLite; operators in operator-only YAML config.

### 3.12 Platform Interfaces (Discovered in M0)

The PRD's surface against the existing platform capabilities:

| Interface | Infrastructure Present | M0 Usage | Integration Pattern for v2 |
|-----------|------------------------|----------|---------------------------|
| Logging / Observability | `tracing` + JSON `tracing-subscriber` | All operational logs route through `tracing` macros | M2+ continues; audit log is a separate write path (DB + JSONL) |
| Configuration | YAML + ArcSwap + `${VAR}` expansion | All config from a single YAML file | M2+ adds a SQLite store for agent/token/audit state, layered alongside YAML; M5 adds `SecretBackend` trait abstraction |
| Authentication | Single static bearer in `inbound_auth`, `secrecy::SecretString` in memory | Process-wide static-token check | M2 replaces with `AgentAuthenticator` trait (D-7); bearer is one impl, mTLS arrives in M6 |
| Authorization | None beyond the bearer presence check | — | M2 introduces per-agent allowlist/denylist on tools; tool discovery filters by allowlist; proxy enforces per-call (R-F6) |
| TLS | `reqwest` uses `rustls-tls` outbound | Outbound TLS to upstreams | M4 adds inbound TLS for admin HTTPS listener; M6 adds mTLS validation (CRL + local blocklist per Q-10) |
| Audit | None | — | M3 introduces SQLite audit table + optional JSONL secondary sink (PRD §14.1 #6); M2 lays the schema |
| Metrics | None | — | M3+ optional Prometheus exposition on separate port (INF-14, Q-19) |
| Health checks | `/health` (liveness + nice-to-have data) | systemd / Ansible probe target | M2 splits into k8s-style `/livez`, `/readyz`, `/version` (INF-3, Q-18) |
| Process supervision | `tokio::signal::ctrl_c` + `axum::serve(...).with_graceful_shutdown(...)` | SIGINT only; no SIGTERM handling, no drain window | M1 adds SIGTERM handling and configurable drain window (INF-1) |
| Egress / network | Optional HTTP CONNECT proxy via `egress_proxy` URL + `cloud: true` per tool | Per-tool routing via `cloud: bool` | M1 renames to `egress: direct | proxied` with shim (R-F13, INF-15); M5 adds systemd hardening at the OS layer |
| Persistence | None (YAML only) | — | M2 adds SQLite + `sqlx::migrate!` (Q-5); WAL mode + tuned PRAGMAs (INF-21, Q-16) |

### 3.13 Responsibility Matrix (M0 → v2 Migration)

How M0's responsibilities migrate into v2 components. This is preview-only; the full component decomposition lives in §4.2 once Phase 5 runs.

| Responsibility | M0 Location | v2 Disposition |
|---------------|-------------|----------------|
| Process bootstrap | `src/main.rs` | Stays in `main.rs`; gains startup-check sequencing (INF-2), drain-window handling (INF-1) |
| HTTP listener binding | `src/main.rs` | Splits into agent listener (existing) + admin Unix socket (M2) + admin HTTPS listener (M4 optional) + bootstrap-only listener (M6 optional) + metrics listener (Q-19 optional) |
| Router assembly | `src/app.rs` | One router per listener; each carries its own middleware stack |
| Inbound auth (bearer) | `src/auth.rs::auth_middleware` | Becomes one impl of `AgentAuthenticator` (D-7); structured-token verification (INF-5); listener-specific middleware |
| YAML config | `src/config.rs` | Stays; gains `deny_unknown_fields` (INF-17), `egress` field (R-F13), per-tool body/timeout/response controls (R-F12, R-F15), `auth_mode` listener-level field (R-F16) |
| Env-var expansion | `src/config.rs::expand_env_vars` (pre-parse, textual) | Pre-parse textual expansion is removed (INF-23); replaced by field-scoped expansion on string-shaped secret fields (back-compat, deprecated path) plus a typed `SecretRef` form for new deployments. M5's `SecretBackend` trait integrates with the typed form |
| Tool discovery | `src/app.rs::tools_handler` | Add per-agent filtering by allowlist/denylist (R-F6, UC-7) |
| Proxy forwarding | `src/proxy.rs::proxy_handler` | Switch to streaming body (M1, R-N6); add per-call audit write (M3); add response controls (M7) |
| Health endpoint | `src/app.rs::health_handler` | Split into `/livez`, `/readyz`, `/version` (INF-3, Q-18) |
| Logging | `src/telemetry.rs` | Stays |
| Metrics | (none) | New: separate listener with Prometheus exposition (INF-14, Q-19) |
| Identity / agent records | (none) | New: SQLite-backed (M2); accessed via repository module |
| Bootstrap tokens | (none) | New: SQLite-backed (M2); admin endpoints to mint/list/revoke |
| Audit log | (none) | New: SQLite write path + optional JSONL sink (M3) |
| Operator credentials | (none) | New: filesystem config, argon2-hashed (Q-4); operator-creds module |
| Admin protocol | (none) | New: `/admin/agent/*` and `/admin/operator/*` namespaces (D-3); CLI subcommands talk to it via Unix socket (R-F9) |
| Drain on shutdown | `tokio::signal::ctrl_c` only | Extended to SIGTERM + configurable window (INF-1) |

---

## 4. Detailed Design

This section turns the §5 component sketch (C-1..C-20), the §5 schema sketch, and the §2 resolutions into an implementable design. The traceability matrix in §4.1 ensures every UC and inferred requirement maps to one or more components; per-component specs (§4.2) carry method shapes and boundaries; the layer view (§4.3) maps components onto the M0-extended architecture from §3.3; systemic interfaces (§4.4) wire components into the platform's logging, metrics, TLS, and persistence capabilities; sequences (§4.5) walk the load-bearing flows; the consolidated data model (§4.6) is the M2 DDL.

### 4.1 UC Traceability Matrix

Every UC and inferred requirement maps to at least one component below. Components are introduced in §4.2; the milestone column indicates when the component first lands.

| Component | Covers UCs | Covers Requirements | Milestone |
|-----------|-----------|---------------------|-----------|
| **C-1: Agent listener** | UC-3, UC-6, UC-7, UC-13 | R-F1, R-F2, R-F6, R-F12, R-F13, R-N6, R-N8, INF-1, INF-3, INF-15, INF-25 | M0 (evolves M1, M3, M7) |
| **C-2: Admin Unix socket** | UC-1, UC-2, UC-3, UC-4, UC-5, UC-7, UC-8, UC-10 | R-F4, R-F5, R-F9, R-N7, INF-7 | M2 |
| **C-3: Admin HTTPS listener** | UC-11 | R-F10, R-N7, INF-8 | M4 |
| **C-4: Bootstrap-only listener** | UC-1, UC-5, UC-12 | R-F4 (register-subset), R-N7, D-10, Q-3 | M6 |
| **C-5: Metrics listener** | (operational) | INF-14, R-N9 (operational defensibility) | M3+ (optional) |
| **C-6: AgentAuthenticator + bearer impl** | UC-6, UC-12 | R-F3, R-F4, R-F16, R-N4, INF-5, INF-13 | M2 (mTLS impl in M6) |
| **C-7: OperatorAuthenticator** | UC-1, UC-4, UC-8, UC-11 | R-F5, R-N7, R-N10 | M2 |
| **C-8: AgentRepository** | UC-1, UC-2, UC-3, UC-4 | R-F3, R-F8, INF-9, INF-10, INF-11 | M2 |
| **C-9: BootstrapTokenRepository** | UC-5 | R-F11, INF-10, INF-13, Q-8 | M2 |
| **C-10: AuditRepository** | UC-4, UC-8, UC-10 | R-F7, R-F14, R-N9, INF-12, INF-13, INF-19, INF-26 | M3 (schema in M2) |
| **C-11: JsonlAuditSink** | UC-8 | R-F7, INF-22, PRD §14.1 #6 | M3 (optional) |
| **C-12: AdminService** | UC-1, UC-2, UC-3, UC-4, UC-5, UC-7, UC-8, UC-10, UC-11 | R-F4, R-F5, R-F6, R-F11, R-F14, INF-9, INF-10, INF-13 | M2 |
| **C-13: ProxyEngine** | UC-6, UC-9, UC-13 | R-F1, R-F2, R-F6, R-F12, R-F13, R-F15, R-F18, R-N6, INF-15, INF-18, INF-20, INF-25 | M1 (audit M3, response controls M7) |
| **C-14: SecretBackend trait + EnvBackend** | UC-6, UC-9, UC-13 | R-F2, R-F17, R-N2, INF-4, INF-23 | M2 (env); M5 (file-sealed, Vault interface) |
| **C-15: RateLimiter** | UC-4 (revocation defensibility) | R-N7, INF-6, Q-15 | M2 |
| **C-16: MtlsValidator** | UC-12 | R-F16, INF-13, Q-10 | M6 |
| **C-17: ResponseControls** | UC-6 (defense-in-depth) | R-F15 | M7 |
| **C-18: ConfigLoader** | UC-1, UC-13 | R-F2, R-F13, R-F16, R-N5, INF-15, INF-16, INF-17, INF-23, INF-24 | M0 (evolved M1, M2) |
| **C-19: MigrationRunner** | (cross-cutting) | R-F8, R-N1, INF-11, Q-5 | M2 |
| **C-20: ShutdownCoordinator** | UC-6 (long-running streams) | R-F12, INF-1 | M1 |

**Inferred requirements coverage:** INF-1..INF-26 are each addressed by one or more of C-1..C-20 above. INF-2 (startup ordering), INF-21 (WAL PRAGMAs), and INF-26 (audit-write strategy) are cross-cutting concerns realized inside C-19, C-10, and C-13 respectively.

**Use case coverage check:** UC-1..UC-13 each appear in at least one component row.

---

### 4.2 Component Architecture

#### 4.2.1 Component Inventory

| Component | Type | Boundary (in / out) | Primary responsibility | Depends on |
|-----------|------|---------------------|------------------------|------------|
| **C-1: Agent listener** | service (process-level) | TCP bind, agent-side router, agent-auth middleware, capacity admission / not: admin operations, persistence | Receive agent traffic, route to ProxyEngine or `/healthz`/`/readyz`/`/version`/`/tools` | C-6, C-13, C-15, C-18, C-20 |
| **C-2: Admin Unix socket** | service (process-level) | UDS bind, admin-side router for both `/admin/agent/*` and `/admin/operator/*`, dual-layer access (filesystem + creds) / not: agent traffic | Local admin path; accepts CLI calls | C-6, C-7, C-12, C-15, C-18 |
| **C-3: Admin HTTPS listener** | service (process-level) | TLS-terminated HTTPS bind, same admin routes as C-2, off-by-default / not: agent traffic, plaintext HTTP | Remote admin path | C-6, C-7, C-12, C-15, C-18 (M4 onward) |
| **C-4: Bootstrap-only listener** | service (process-level) | TLS-terminated HTTPS bind, only `POST /admin/agent/register` accepted / not: any other operation | Onboarding agents in mtls-only deployments | C-9, C-12, C-15, C-18 |
| **C-5: Metrics listener** | service (process-level) | TCP bind, `/metrics` only, unauthenticated, off-by-default / not: any other endpoint | Prometheus-pull exposition | C-18 |
| **C-6: AgentAuthenticator + bearer impl** | trait + impl module | Resolve presented credential to `Agent` record / not: authorization, audit | Authentication for agent listener | C-8, C-15 |
| **C-7: OperatorAuthenticator** | module | Resolve presented operator credential to `Operator` record / not: agent auth | Authentication for admin endpoints | (filesystem) C-15 |
| **C-8: AgentRepository** | repository module | CRUD against `agents` table / not: business rules | Persist + query agent records | sqlx pool, C-19 |
| **C-9: BootstrapTokenRepository** | repository module | CRUD + atomic `consume` against `bootstrap_tokens` / not: bootstrap-token *minting* policy (lives in C-12) | Persist + atomically consume bootstrap tokens | sqlx pool, C-19 |
| **C-10: AuditRepository** | repository module | Insert + query against `audit` table; class-aware retention worker / not: JSONL fan-out | Persist audit events; serve audit queries | sqlx pool, C-19 |
| **C-11: JsonlAuditSink** | module + background task | Bounded mpsc channel + drop-newest writer; daily/size rotation / not: SQLite write | Best-effort fan-out of audit events to JSONL | (filesystem) |
| **C-12: AdminService** | service module | Pure business logic for all admin operations: register, rotate, revoke, mint bootstrap, query audit, export, list-tools-for-operator / not: HTTP framing, persistence I/O | Single business-logic surface called by all admin transports | C-8, C-9, C-10, C-14, C-18 |
| **C-13: ProxyEngine** | service module | Per-tool client pool, request rewrite, credential injection, streaming-pass-through, response-controls, audit-write / not: agent identity, allowlist enforcement (delegated to caller) | Forward credentialed HTTP to upstreams | C-10, C-14, C-17, C-18 |
| **C-14: SecretBackend trait + EnvBackend** | trait + impl module | Resolve `SecretRef` to `SecretString` / not: storage of resolved secrets beyond zeroized in-memory | Provide upstream credentials to ProxyEngine | (env vars) (filesystem M5) |
| **C-15: RateLimiter** | module | Token-bucket per IP + per-target failure counter / not: persisted state | Bound brute-force on `register`/`rotate`/operator endpoints | (in-memory) |
| **C-16: MtlsValidator** | module | Cert chain verification, CRL fetch, local blocklist consultation, identity extraction / not: TLS termination | Validate client certs for mTLS auth | (filesystem) (network for CRL) |
| **C-17: ResponseControls** | module | Apply max-size cap, content-type allowlist, regex redaction to non-streaming responses; total-size cap on streaming / not: streaming-chunk inspection | Per-tool response policy enforcement | C-18 |
| **C-18: ConfigLoader** | module | Load + validate YAML, deprecation registry, ArcSwap-backed hot reload, atomic-validate-then-swap, listener-shape detection / not: persisted state | Single source of `AppConfig` truth at runtime | (filesystem) C-14 |
| **C-19: MigrationRunner** | module | Apply embedded migrations at startup; verify schema version / not: data backfills | Database schema evolution | sqlx |
| **C-20: ShutdownCoordinator** | module | SIGINT/SIGTERM handlers, drain timer, listener-stop signaling / not: per-request cancellation | Graceful shutdown of all listeners | C-1, C-2, C-3, C-4, C-5 |

#### 4.2.2 Component Dependency Diagram

```
                         ┌─────────────────────┐
                         │ C-18 ConfigLoader   │
                         │ (ArcSwap<AppConfig>)│
                         └──────────┬──────────┘
                                    │ all components read config
                                    ▼
   ┌────────────┐   ┌────────────┐   ┌────────────┐   ┌────────────┐   ┌────────────┐
   │ C-1 Agent  │   │ C-2 Admin  │   │ C-3 Admin  │   │ C-4 Boot   │   │ C-5 Metrics│
   │  listener  │   │   UDS      │   │  HTTPS     │   │  -only     │   │  listener  │
   │  (M0/M1)   │   │   (M2)     │   │   (M4)     │   │   (M6)     │   │   (M3+)    │
   └─────┬──────┘   └─────┬──────┘   └─────┬──────┘   └─────┬──────┘   └────────────┘
         │                │                │                │
         │                ├────────────────┤                │
         │                │                │                │
         │  agent-auth    │  operator-auth + agent-auth     │ bootstrap-token
         │     (C-6)      │     (C-6, C-7)                  │   verify (C-9)
         │                │                │                │
         │                │  rate-limit (C-15) on all admin │
         │                │                │                │
         │                ▼                ▼                ▼
         │         ┌──────────────────────────────────┐
         │         │     C-12 AdminService            │
         │         │  (pure business logic; called    │
         │         │   identically from C-2/C-3/C-4)  │
         │         └────┬──────┬──────┬──────┬────────┘
         │              │      │      │      │
         │              ▼      ▼      ▼      ▼
         │      ┌──────┐  ┌──────┐  ┌──────┐  ┌──────┐
         │      │ C-8  │  │ C-9  │  │ C-10 │  │ C-14 │
         │      │Agent │  │Boot  │  │Audit │  │Secret│
         │      │ Repo │  │ Repo │  │ Repo │  │Bcknd │
         │      └──┬───┘  └──┬───┘  └──┬───┘  └──┬───┘
         │         └─────────┴────────┬┘         │
         │                            ▼          │
         │                      ┌──────────┐     │
         │                      │  sqlx    │     │
         │                      │  pool    │◄────┤  (resolved at startup;
         │                      │  + WAL   │     │   applied to AppState)
         │                      └────┬─────┘     │
         │                           │           │
         │                           ▼           │
         │                      ┌──────────┐     │
         │                      │  SQLite  │     │
         │                      │ locksmith│     │
         │                      │   .db    │     │
         │                      └──────────┘     │
         │                                       │
         │   ┌─── proxy hot path ──────────────┐ │
         ▼   ▼                                 │ │
   ┌─────────────────────┐                     │ │
   │ C-13 ProxyEngine    │─── resolves ────────┘ │
   │  - per-tool client  │     credentials       │
   │    pool (INF-25)    │                       │
   │  - streaming body   │── audit-write ──────► C-10
   │    (R-N6)           │                       │
   │  - capacity admit   │                       │
   │    (INF-18)         │                       │
   │  - response ctrls   │                       │
   │    (C-17, M7)       │                       │
   └──────┬──────────────┘                       │
          │                                      │
          │  optional fan-out                    │
          │  (PRD §14.1 #6)                      │
          ▼                                      │
   ┌─────────────────────┐                       │
   │ C-11 JsonlAuditSink │                       │
   └──────────┬──────────┘                       │
              ▼                                  │
       ┌──────────────┐                          │
       │ audit.jsonl  │                          │
       └──────────────┘                          │
                                                 │
       ┌─────────────────────┐                   │
       │ C-19 MigrationRunner│ ─ at startup ─────┘
       └─────────────────────┘
       ┌─────────────────────┐
       │ C-20 Shutdown       │ ─ signals all listeners
       │     Coordinator     │
       └─────────────────────┘
       ┌─────────────────────┐
       │ C-16 MtlsValidator  │ (M6, called by C-6 mTLS impl)
       └─────────────────────┘
```

---

#### 4.2.3 C-1: Agent listener

**Type:** service (process-level)
**Location:** `src/listeners/agent.rs` (new module under reorganized `src/listeners/`)
**Dependencies:** C-6, C-13, C-15, C-18, C-20

The agent listener is the M0 listener evolved across milestones. Routes:

| Method | Path | Auth | Handler delegates to |
|--------|------|------|----------------------|
| `GET` | `/livez` | none | inline (always 200 unless process broken) |
| `GET` | `/readyz` | none | inline (DB ping + listener-bound check + required-backend check; INF-3 / Q-18) |
| `GET` | `/version` | none | inline (build SHA, build date, crate version) |
| `GET` | `/tools` | C-6 agent-auth | `AdminService.list_tools_for_agent(authenticated_agent)` |
| `ANY` | `/api/{tool}/{*path}` | C-6 agent-auth | C-13 `ProxyEngine.forward(authenticated_agent, tool, req)` |

Middleware stack (outer → inner):
1. `tower_http::trace::TraceLayer` (existing M0)
2. C-15 RateLimiter (per-endpoint thresholds; tool proxy traffic is *not* rate-limited at this listener — that would defeat agent throughput)
3. C-6 AgentAuthenticator (skipped on `/livez`, `/readyz`, `/version`)
4. capacity admission (C-13 hooks streaming-cap check before forwarding)

`/readyz` semantics (INF-3 + A-4 assumption from §2.1): green when (DB reachable) AND (agent listener bound) AND (every tool without `on_secret_failure: degraded` has a resolved `SecretBackend`). Tools opted into degraded mode do not fail readiness.

*Traces to: UC-3, UC-6, UC-7, UC-13; R-F1, R-F2, R-F6, R-F12, R-F13, R-N6, R-N8; INF-1, INF-3, INF-15, INF-25.*

#### 4.2.4 C-2: Admin Unix socket

**Type:** service (process-level)
**Location:** `src/listeners/admin_uds.rs`
**Dependencies:** C-6, C-7, C-12, C-15, C-18

Binds to the configured UDS path (default `/run/locksmith/admin.sock`) with mode 0660, owner `locksmith`, group configurable (default `locksmith`). On startup, removes any stale socket file from a previous unclean shutdown after a sanity check (file is a socket, no process holds it).

Routes split into two sub-routers:

| Namespace | Auth | Handler |
|-----------|------|---------|
| `/admin/agent/*` | C-6 agent-auth | thin axum handlers → C-12 |
| `/admin/operator/*` | C-7 operator-auth | thin axum handlers → C-12 |

The middleware stack on operator endpoints applies *both* the filesystem permission gate (enforced by the OS at connect time) and the operator-credential gate (per INF-7 / Q-24). Filesystem failure → caller sees `permission denied` at connect; credential failure → `401 invalid_credential`.

The *exact same* axum handler functions are reused on C-3 (admin HTTPS) by composing them into a different router. Identical behavior is the M2/M4 contract.

*Traces to: UC-1, UC-2, UC-3, UC-4, UC-5, UC-7, UC-8, UC-10; R-F4, R-F5, R-F9, R-N7; INF-7.*

#### 4.2.5 C-3: Admin HTTPS listener

**Type:** service (process-level), optional
**Location:** `src/listeners/admin_https.rs` (M4)

Same router shape as C-2. Bound to a separate port (default 9201) with TLS termination via rustls (`reqwest`'s rustls is already a dep, but we need rustls-pemfile + tokio-rustls for the server side).

Differences from C-2:
- Connections arrive over TCP+TLS, not UDS. No filesystem permission layer.
- Accepts both bearer (M4) and mTLS (M6, when `auth_mode` includes mtls) for *both* agents and operators.
- Off-by-default; only bound when `listen.admin_https.enabled: true`.
- TLS cert/key file paths are listener-shape config (R-N5 carve-out): cert rotation requires restart.

*Traces to: UC-11; R-F10, R-N7; INF-8.*

#### 4.2.6 C-4: Bootstrap-only listener

**Type:** service (process-level), optional
**Location:** `src/listeners/bootstrap.rs` (M6)

Server-TLS without client mTLS, single endpoint `POST /admin/agent/register`. Off-by-default; only bound when `listen.bootstrap.enabled: true`. Locked down via network policy by the operator (Tailscale, localhost-only, etc.).

The handler delegates to `C-12 AdminService.register_agent` exactly as the other listeners do. Bootstrap-token verification is the only auth (D-10).

*Traces to: UC-1, UC-5, UC-12; R-F4 (register-subset), R-N7, D-10.*

#### 4.2.7 C-5: Metrics listener

**Type:** service (process-level), optional
**Location:** `src/listeners/metrics.rs` (M3+)

Single route: `GET /metrics` returning Prometheus text exposition. Unauthenticated. Bound to a configurable port (default 9091). Off-by-default.

Metrics registry is global (lazy_static or `metrics` crate's global recorder). Counters and gauges are described in §4.4.2.

*Traces to: INF-14; R-N9 (operational defensibility).*

#### 4.2.8 C-6: AgentAuthenticator + bearer impl

**Type:** trait + impl module
**Location:** `src/auth/mod.rs`, `src/auth/bearer.rs`, `src/auth/mtls.rs` (M6)

```rust
#[async_trait]
pub trait AgentAuthenticator: Send + Sync {
    /// Resolve the authenticated agent for a request, or return AuthError.
    /// Implementations must be constant-time on secret comparison (INF-5).
    async fn authenticate(&self, req: &Request<Body>) -> Result<Agent, AuthError>;
}

pub enum AuthError {
    MissingCredential,
    InvalidCredential,         // wire-form: `401 { "error": "invalid_credential" }`
    Revoked,
    Expired,
    RateLimited { retry_after: Duration },
    BackendError(anyhow::Error),  // 5xx; logged
}
```

**Bearer impl (`src/auth/bearer.rs`):**

1. Extract `Authorization: Bearer <token>` header. Token shape: `lk_<public_id_b64url_22chars>.<secret_b64url_43chars>` (128-bit + 256-bit, INF-5).
2. Parse into `(public_id, secret)`. Malformed → `InvalidCredential`.
3. `C-8 AgentRepository.get_active_by_public_id(&public_id)` → `Option<AgentRecord>`. Lookup is O(log n) on the unique index — *the public id is not secret*, so the timing characteristic is acceptable (Q-14, R-3 risk acknowledgement). On miss, do a *decoy* argon2-verify against a stored zero-value pepper to keep miss-vs-hit timing similar (defensive; not strictly required at 2^128 entropy).
4. `argon2::verify_encoded(&record.secret_hash, secret.as_bytes())` — constant-time; on mismatch → `InvalidCredential`, increment per-target failure counter (C-15).
5. If `record.revoked_at.is_some()` → `Revoked` + audit `auth_failure event_class=security`.
6. If `record.expires_at.is_some_and(|e| e < now)` → `Expired` + audit.
7. Update `record.last_used_at` (best-effort; UPDATE inside the auth path is OK at our scale, but uses a sub-millisecond txn). Failure to update is logged but non-fatal.
8. Return `Agent { public_id, name, allowlist, denylist, ... }`.

**mTLS impl (`src/auth/mtls.rs`, M6):** delegates cert validation to C-16 MtlsValidator; extracts identity per `mtls.identity_field` config; looks up agent by `cert_identity` column.

**`auth_mode: both` behavior:** the agent listener middleware tries mTLS first (if a client cert was presented during TLS), falls back to bearer if no cert. Audit records `auth_method: mtls` or `bearer` (INF-13).

*Traces to: UC-6, UC-12; R-F3, R-F4, R-F16, R-N4; INF-5, INF-13.*

#### 4.2.9 C-7: OperatorAuthenticator

**Type:** module
**Location:** `src/auth/operator.rs`

Reads operator records from the file at `operator_credentials_path` at startup; reloads on SIGHUP or file change. Each record:

```rust
pub struct OperatorRecord {
    pub name: String,
    pub token_hash: String,         // argon2-encoded
    pub scope: Option<OperatorScope>,  // reserved (D-6)
}
```

`authenticate(req: &Request) -> Result<Operator, AuthError>`:

1. Extract `Authorization: Bearer lk_op_<public_id>.<secret>` (operator token namespace `lk_op_` distinguishes from agent tokens).
2. Lookup by `public_id` → record. Miss → `InvalidCredential` + decoy verify.
3. argon2-verify. Mismatch → `InvalidCredential` + per-target failure counter.
4. Return `Operator { name, scope }`.

If the operator credentials file is missing at startup, `C-19/C-18` cause Locksmith to fail-fast (operator credentials are R-N10's recovery principal; missing file = unrecoverable state).

*Traces to: UC-1, UC-4, UC-8, UC-11; R-F5, R-N7, R-N10.*

#### 4.2.10 C-8: AgentRepository

**Type:** repository module
**Location:** `src/repo/agent.rs`

```rust
pub struct AgentRepository { pool: SqlitePool }

impl AgentRepository {
    /// Insert a new agent. Returns the new public_id and the cleartext token (returned exactly once, R-N4).
    /// Fails with `AgentNameConflict` on UNIQUE(name) violation.
    pub async fn create(
        &self,
        name: &str,
        description: Option<&str>,
        allowlist: Option<&[String]>,
        denylist: Option<&[String]>,
        metadata: Option<&serde_json::Value>,
        expires_at: Option<i64>,
    ) -> Result<(String, SecretString), RepoError>;

    /// Lookup by public_id. Excludes revoked unless include_revoked=true.
    pub async fn get_active_by_public_id(&self, public_id: &str)
        -> Result<Option<AgentRecord>, RepoError>;

    pub async fn get_by_name(&self, name: &str) -> Result<Option<AgentRecord>, RepoError>;

    pub async fn list(&self, include_revoked: bool) -> Result<Vec<AgentRecord>, RepoError>;

    pub async fn update_policy(
        &self,
        public_id: &str,
        allowlist: Option<Vec<String>>,
        denylist: Option<Vec<String>>,
        metadata: Option<serde_json::Value>,
        expires_at: Option<i64>,
    ) -> Result<AgentRecord, RepoError>;

    /// Soft-delete: sets revoked_at = now. Idempotent (re-revoke is no-op).
    pub async fn revoke(&self, public_id: &str) -> Result<(), RepoError>;

    /// Atomic rotate: validates current secret, generates new, updates secret_hash,
    /// returns cleartext new token. INF-9: first-committer wins on concurrent calls.
    pub async fn rotate(&self, public_id: &str, current_secret: &SecretString)
        -> Result<SecretString, RepoError>;

    pub async fn touch_last_used(&self, public_id: &str) -> Result<(), RepoError>;

    /// For mTLS impl (M6): map cert identity to agent record.
    pub async fn get_by_cert_identity(&self, identity: &str)
        -> Result<Option<AgentRecord>, RepoError>;
}
```

**Concurrency semantics:**
- `create`: relies on `agents.name UNIQUE` constraint. Two concurrent `create` with same name → SQLite returns `SQLITE_CONSTRAINT_UNIQUE` for the second → mapped to `RepoError::AgentNameConflict` (INF-10).
- `rotate`: SQL is `UPDATE agents SET secret_hash = ? WHERE public_id = ? AND secret_hash = ?` — the WHERE clause includes the *expected current* hash, so concurrent rotate calls only one succeeds (`rows_affected == 1`); the other sees `rows_affected == 0` and returns `RepoError::RotationInProgress` (INF-9).

*Traces to: UC-1, UC-2, UC-3, UC-4; R-F3, R-F8; INF-9, INF-10.*

#### 4.2.11 C-9: BootstrapTokenRepository

**Type:** repository module
**Location:** `src/repo/bootstrap.rs`

```rust
pub struct BootstrapTokenRepository { pool: SqlitePool }

impl BootstrapTokenRepository {
    pub async fn mint(
        &self,
        scope: BootstrapScope,
        created_by: &str,
        expires_at: Option<i64>,
        single_use: bool,
    ) -> Result<(String, SecretString), RepoError>;

    pub async fn list(&self, include_used: bool, include_revoked: bool)
        -> Result<Vec<BootstrapTokenRecord>, RepoError>;

    /// Atomic consume. Returns Ok(scope) if token was unused, unrevoked, unexpired;
    /// Err(InvalidCredential) otherwise. The atomic step uses:
    ///   UPDATE bootstrap_tokens SET used_at = ?, used_by_agent_id = ?
    ///   WHERE public_id = ? AND used_at IS NULL AND revoked_at IS NULL
    ///     AND (expires_at IS NULL OR expires_at > ?)
    ///     AND verify(secret_hash, ?)
    /// Wait — we can't do argon2 verify in SQL. Two-step:
    ///   1. SELECT secret_hash, scope FROM bootstrap_tokens WHERE public_id = ?
    ///      AND used_at IS NULL AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > ?)
    ///   2. argon2::verify in Rust
    ///   3. UPDATE ... SET used_at = ? WHERE public_id = ? AND used_at IS NULL  (atomic guard)
    /// If step 3 affects 0 rows, another caller raced us → return InvalidCredential
    /// (specifically, the audit event is bootstrap_reuse_attempt — INF-13).
    pub async fn consume(
        &self,
        public_id: &str,
        secret: &SecretString,
        agent_id: i64,
    ) -> Result<BootstrapScope, RepoError>;

    pub async fn revoke(&self, public_id: &str) -> Result<(), RepoError>;
}
```

**Reuse-attempt audit (INF-13, Q-8):** any failure mode in `consume` that resolves to `InvalidCredential` for a *known* `public_id` (i.e., the token existed but was already consumed, revoked, or expired) is audited as `event=bootstrap_reuse_attempt`, `event_class=security`. A genuinely-unknown `public_id` (no row) is audited as `event=auth_failure` to keep the security-event class focused on actual reuse signal.

*Traces to: UC-5; R-F11; INF-10, INF-13; Q-8.*

#### 4.2.12 C-10: AuditRepository

**Type:** repository module + retention worker
**Location:** `src/repo/audit.rs`, `src/repo/audit/retention.rs`

```rust
pub struct AuditRepository { pool: SqlitePool, jsonl_sink: Option<Arc<JsonlAuditSink>> }

impl AuditRepository {
    /// Synchronous write per INF-26 / Q-28. Returns when the row is committed.
    /// On error: log + bump `audit_write_errors_total` metric, but do NOT
    /// fail the calling request (audit failure must not block proxy traffic).
    /// The optional jsonl_sink fan-out happens after SQLite commit.
    pub async fn record(&self, event: AuditEvent) -> Result<(), RepoError>;

    pub async fn query(&self, filter: AuditFilter, page: AuditPage)
        -> Result<AuditQueryResult, RepoError>;
}

pub struct AuditEvent {
    pub ts: i64,                    // unix millis
    pub event_class: EventClass,    // proxy | operator | security
    pub event: String,              // proxy_request | agent_register | rotation | ...
    pub agent_public_id: Option<String>,
    pub operator_name: Option<String>,
    pub tool: Option<String>,
    pub upstream_host: Option<String>,
    pub method: Option<String>,
    pub path: Option<String>,
    pub status: Option<u16>,
    pub latency_ms: Option<u64>,
    pub decision: Decision,         // allowed | denied | error
    pub auth_method: Option<AuthMethod>,
    pub origin_ip: Option<String>,
    pub details: Option<serde_json::Value>,
}
```

**Retention worker (`audit/retention.rs`):** runs hourly via `tokio::time::interval`. SQL:

```sql
-- per-class time-based prune
DELETE FROM audit
 WHERE event_class = 'proxy'
   AND ts < ?  -- now - audit.proxy_retention_days
 LIMIT 10000;  -- iterate to avoid one giant transaction

DELETE FROM audit
 WHERE event_class IN ('operator','security')
   AND ts < ?  -- now - audit.operator_retention_days
 LIMIT 10000;

-- row-count safety cap (INF-19): if total rows > cap, prune oldest proxy first
SELECT COUNT(*) FROM audit;  -- fast on indexed count
-- if > cap, DELETE FROM audit WHERE event_class = 'proxy' AND id IN (SELECT id ... LIMIT excess);
```

The retention worker is single-threaded; pruning happens outside the proxy hot path.

**Audit-write strategy default is synchronous (INF-26).** The fallback async-batched mode is gated by the M3 benchmark task (T3.X in §6).

*Traces to: UC-4, UC-8, UC-10; R-F7, R-F14, R-N9; INF-12, INF-13, INF-19, INF-26.*

#### 4.2.13 C-11: JsonlAuditSink

**Type:** module + background task
**Location:** `src/audit/jsonl.rs`

```rust
pub struct JsonlAuditSink {
    sender: mpsc::Sender<AuditEvent>,    // bounded, default capacity 10000
    dropped_counter: Counter,            // metrics
}

impl JsonlAuditSink {
    pub fn spawn(config: &JsonlConfig) -> Result<Self, SinkError>;

    /// Non-blocking enqueue. On full channel: drop the new event,
    /// increment audit_jsonl_dropped_total. SQLite remains canonical.
    pub fn try_record(&self, event: &AuditEvent);
}
```

The spawned task drains the channel, writes one JSON line per event to the configured path, rotates on day boundary or 100MB cap (whichever first), names rotated files `audit-YYYYMMDD.jsonl[.N]`.

**Startup-unreachable behavior (INF-22 / Q-21):** on `spawn`, attempts to open the file. On failure: returns `SinkError`. The caller (typically C-18 ConfigLoader) then either fails-fast (if `audit.jsonl_required: true`) or starts with `jsonl_sink: None` + logs a warning + sets `audit_jsonl_disabled = 1` gauge.

**Schema (mirror SQLite columns + `schema_version`):**

```json
{
  "schema_version": 1,
  "ts": 1745889600000,
  "event_class": "proxy",
  "event": "proxy_request",
  "agent_public_id": "...",
  "operator_name": null,
  "tool": "anthropic",
  "upstream_host": "api.anthropic.com",
  "method": "POST",
  "path": "/v1/messages",
  "status": 200,
  "latency_ms": 1832,
  "decision": "allowed",
  "auth_method": "bearer",
  "origin_ip": "10.0.0.42",
  "details": {}
}
```

*Traces to: UC-8; R-F7; INF-22; PRD §14.1 #6.*

#### 4.2.14 C-12: AdminService

**Type:** service module (pure business logic)
**Location:** `src/admin/service.rs`

The single business-logic surface for admin operations. Both C-2 (UDS handlers), C-3 (HTTPS handlers), and C-4 (bootstrap-only handlers) are thin axum wrappers that:
1. Extract authenticated `Agent` or `Operator` from middleware-populated request extensions.
2. Parse the request body into a typed input.
3. Call into `AdminService`.
4. Render the result as JSON with the appropriate status code.

```rust
pub struct AdminService {
    agents: AgentRepository,
    bootstrap: BootstrapTokenRepository,
    audit: AuditRepository,
    config: Arc<ArcSwap<AppConfig>>,
    secret_backend: Arc<dyn SecretBackend>,
}

impl AdminService {
    // --- Agent self-service ---
    pub async fn register_agent(&self, input: RegisterInput, origin: OriginInfo)
        -> Result<RegisterOutput, AdminError>;
    pub async fn get_agent_status(&self, agent: &Agent)
        -> Result<AgentStatusOutput, AdminError>;
    pub async fn rotate_agent(&self, agent: &Agent, current_secret: &SecretString)
        -> Result<RotateOutput, AdminError>;
    pub async fn deregister_agent(&self, agent: &Agent)
        -> Result<(), AdminError>;
    pub async fn list_tools_for_agent(&self, agent: &Agent)
        -> Result<Vec<ToolInfo>, AdminError>;

    // --- Operator ---
    pub async fn list_agents(&self, op: &Operator) -> Result<Vec<AgentInfo>, AdminError>;
    pub async fn get_agent(&self, op: &Operator, public_id: &str)
        -> Result<AgentInfo, AdminError>;
    pub async fn create_agent_as_operator(&self, op: &Operator, input: CreateAgentInput)
        -> Result<RegisterOutput, AdminError>;
    pub async fn modify_agent(&self, op: &Operator, public_id: &str, input: ModifyAgentInput)
        -> Result<AgentInfo, AdminError>;
    pub async fn revoke_agent(&self, op: &Operator, public_id: &str)
        -> Result<(), AdminError>;
    pub async fn mint_bootstrap_token(&self, op: &Operator, input: MintInput)
        -> Result<MintOutput, AdminError>;
    pub async fn list_bootstrap_tokens(&self, op: &Operator)
        -> Result<Vec<BootstrapTokenInfo>, AdminError>;
    pub async fn revoke_bootstrap_token(&self, op: &Operator, public_id: &str)
        -> Result<(), AdminError>;
    pub async fn list_tools_for_operator(&self, op: &Operator)
        -> Result<Vec<ToolInfo>, AdminError>;
    pub async fn query_audit(&self, op: &Operator, filter: AuditFilter, page: AuditPage)
        -> Result<AuditQueryResult, AdminError>;
    pub async fn export_agents_yaml(&self, op: &Operator) -> Result<String, AdminError>;
}
```

Every public method writes an audit row before returning (success or failure path) per R-N9. The transport handlers do not perform business validation — they parse and dispatch only.

*Traces to: UC-1, UC-2, UC-3, UC-4, UC-5, UC-7, UC-8, UC-10, UC-11; R-F4, R-F5, R-F6, R-F11, R-F14; INF-9, INF-10, INF-13.*

#### 4.2.15 C-13: ProxyEngine

**Type:** service module
**Location:** `src/proxy/engine.rs` (M0 `src/proxy.rs` is rewritten in M1)

```rust
pub struct ProxyEngine {
    clients: Arc<RwLock<HashMap<String, Arc<reqwest::Client>>>>,  // INF-25, Q-27
    config: Arc<ArcSwap<AppConfig>>,
    secret_backend: Arc<dyn SecretBackend>,
    audit: AuditRepository,
    capacity: Arc<StreamingCapacity>,  // INF-18, per-agent + global
}

impl ProxyEngine {
    /// Forward a request from `agent` for `tool`. Streams the response.
    pub async fn forward(
        &self,
        agent: &Agent,
        tool_name: &str,
        req: Request<Body>,
    ) -> Response;
}
```

**Forward-flow steps:**

1. **Authorize tool access:** lookup `tool` in `config.tools`; verify `tool ∈ agent.allowlist (or allowlist == None) AND tool ∉ agent.denylist AND credential_present`. Failure → 403 `tool_not_allowed`, audit `event=auth_failure event_class=security decision=denied` + return.
2. **Capacity admit:** `capacity.admit(agent.public_id)`. If global or per-agent at threshold → 503 `streaming_capacity_exceeded` + `Retry-After` + audit `event=streaming_capacity_exceeded event_class=proxy`.
3. **Get pooled client:** look up in `clients` map; if absent, build one with the tool's timeout, idle-timeout, and (when `egress: proxied`) the configured HTTP CONNECT proxy. Insert and return `Arc<Client>`.
4. **Resolve credential:** `secret_backend.resolve(&tool.auth.value)` → `SecretString`. Failure (e.g., env var disappeared after startup) under `degraded` mode → 503 + audit; under `fail-fast` mode → 502 + audit + log severity=error (this should be impossible at runtime if startup checks passed).
5. **Build upstream request:**
   - Method, path-suffix, and body forwarded byte-for-byte.
   - Strip incoming `host`, `authorization`, `x-api-key`, and the configured `tool.auth.header` from headers.
   - Inject `tool.auth.header: <resolved-secret>`.
   - Apply `tool.body_limit_bytes` (default 10 MiB) — body capture switches to streaming when > a small threshold (~64 KiB) but enforces total cap.
6. **Send & stream response:** `client.execute(upstream_req).await` returns headers and a stream. Build the axum response with `Body::from_stream(resp.bytes_stream())`. Apply C-17 ResponseControls *between* upstream stream and response body (size cap on streaming; redaction is non-streaming-only).
7. **On stream end (or error or cancellation):** record `event=proxy_request event_class=proxy` with status, latency, allowed/denied/error decision, auth_method.
8. **On capacity release:** decrement per-agent and global counters in a `Drop` guard so cancellation or panic still releases.

**Egress proxy failure (INF-20):** when `egress: proxied` and the configured proxy returns non-2xx CONNECT or refuses connection → 502 with body `{"error": "egress_proxy_failure", "tool": "..."}`, audit `event=egress_proxy_failure`. Specifically does *not* leak the proxy URL or proxy-side credentials.

*Traces to: UC-6, UC-9, UC-13; R-F1, R-F2, R-F6, R-F12, R-F13, R-F15, R-F18, R-N6; INF-15, INF-18, INF-20, INF-25.*

#### 4.2.16 C-14: SecretBackend trait + EnvBackend

**Type:** trait + impl module
**Location:** `src/secret/mod.rs`, `src/secret/env.rs`, `src/secret/file_sealed.rs` (M5)

```rust
#[async_trait]
pub trait SecretBackend: Send + Sync {
    /// Resolve a SecretRef into a SecretString.
    /// Implementations should zero stale values on Drop.
    async fn resolve(&self, secret_ref: &SecretRef) -> Result<SecretString, BackendError>;

    /// Identifier for diagnostics. Does NOT include any secret material.
    fn kind(&self) -> &'static str;
}

pub enum SecretRef {
    /// Legacy field-scoped string with `${VAR}` patterns (INF-23 deprecated path).
    LegacyString(String),
    /// Typed env-var reference. Optional `prefix` (e.g., "Bearer ") prepended to value.
    FromEnv { var: String, prefix: Option<String> },
    /// File-sealed (M5). Path to encrypted blob.
    FromFileSealed { path: PathBuf },
    /// Vault (post-M5; interface only in v2).
    FromVault { mount: String, path: String, field: String },
    /// AWS Secrets Manager (post-M5; interface only in v2).
    FromAwsSecretsManager { secret_id: String, version_stage: Option<String>, field: Option<String> },
}
```

**EnvBackend:** dispatches on `SecretRef` variant. For `LegacyString`, walks `${VAR}` patterns and substitutes from env (the field-scoped expander, replacing M0's pre-parse expander). For `FromEnv`, reads `var`, prepends `prefix` if any, returns. Missing env var → `BackendError::Missing(var)`.

The startup-resolution policy from INF-4/Q-17 is implemented at the `AppState` construction layer: each tool's `auth.value` is resolved once at startup; the `Result` is stored in a `ToolRuntime` struct and consulted on every request. Hot-reload re-resolves tools whose `SecretRef` changed.

**Future M5 backends:** `FileSealedBackend` decrypts at startup using a key from `systemd-creds` or a configured path. `VaultBackend` (post-M5) and `AwsSecretsManagerBackend` (post-M5) resolve lazily with TTL cache (per Q-12 contract).

*Traces to: UC-6, UC-9, UC-13; R-F2, R-F17, R-N2; INF-4, INF-23.*

#### 4.2.17 C-15: RateLimiter

**Type:** module
**Location:** `src/ratelimit.rs`

In-memory rate limiter. Two structures:

```rust
pub struct PerIpBucket {
    buckets: DashMap<IpAddr, TokenBucket>,
    capacity: u32,
    refill_per_minute: u32,
}

pub struct PerTargetFailureCounter {
    counters: DashMap<String, FailureWindow>,  // public_id → (count, first_failure_ts)
    threshold: u32,                             // default 10
    window: Duration,                           // default 5min
}
```

**Eviction:** both maps include a periodic background scan that drops entries idle for >2× their window. Memory bounded under `O(active_clients × average_keys)`.

**Per-endpoint configuration** flows from C-18 `AppConfig.rate_limit.*`. The middleware stack on C-2 / C-3 / C-4 / C-1 (where applicable) consults these limiters and returns `429 + Retry-After` on overflow + audit `event=rate_limited event_class=security`.

*Traces to: R-N7; INF-6.*

#### 4.2.18 C-16: MtlsValidator

**Type:** module
**Location:** `src/auth/mtls_validator.rs` (M6)

```rust
pub struct MtlsValidator {
    ca_bundle: rustls::RootCertStore,
    crl: Arc<RwLock<CrlState>>,            // refreshed periodically
    blocklist: Arc<RwLock<HashSet<String>>>, // serial numbers, configurable file
    identity_field: IdentityField,          // CN | SAN_DNS | SAN_URI
}

impl MtlsValidator {
    pub fn validate(&self, peer_cert: &rustls::Certificate)
        -> Result<MtlsIdentity, MtlsError>;
}
```

**Validation steps:**
1. Parse cert via `x509-parser`. Reject malformed.
2. Verify against `ca_bundle` (chain validation; expiration check).
3. Check CRL: if cert serial in current CRL → `Revoked`.
4. Check local blocklist: if cert serial in blocklist file → `Revoked`.
5. Extract identity per `identity_field`: CN (Common Name from subject), SAN_DNS (subjectAltName DNS entry), SAN_URI (subjectAltName URI entry).
6. Return `MtlsIdentity { value, serial, expires_at }`.

**CRL refresh:** background task fetches `mtls.crl.url` every `mtls.crl.refresh_interval_seconds`. On fetch failure: keep existing CRL; log warning; bump `mtls_crl_refresh_failures_total`. CRL freshness is exposed as a `mtls_crl_age_seconds` gauge.

**Local blocklist file format:** one cert serial per line, comments allowed (`#`). Reloaded on file change (via the same hot-reload mechanism as the main config).

*Traces to: UC-12; R-F16; INF-13; Q-10.*

#### 4.2.19 C-17: ResponseControls

**Type:** module
**Location:** `src/proxy/response_controls.rs` (M7)

```rust
pub struct ResponseControls {
    max_size_bytes: Option<u64>,
    content_type_allowlist: Option<HashSet<String>>,
    redaction_patterns: Vec<RedactionPattern>,  // pre-compiled regex + replacement
}

impl ResponseControls {
    /// For non-streaming responses: read body, apply size cap, content-type check, redaction.
    /// For streaming responses: enforce only total-size cap; redaction not applied to streaming.
    pub async fn apply(
        &self,
        upstream_resp: reqwest::Response,
        is_streaming: bool,
    ) -> Result<axum::response::Response, ControlsError>;
}
```

**Streaming handling:** the size cap is enforced via a `Stream` wrapper that counts bytes; on cap-exceeded, the stream returns an error chunk and the response is closed; agent sees a truncated response with a `x-locksmith-truncated: true` trailer. Redaction is *not* applied to streaming responses (regex-on-stream is a class of footgun PRD §M7 explicitly disallows).

*Traces to: UC-6 (defense-in-depth); R-F15.*

#### 4.2.20 C-18: ConfigLoader

**Type:** module
**Location:** `src/config/loader.rs` (evolved from M0 `src/config.rs`)

```rust
pub struct ConfigLoader {
    path: PathBuf,
    current: Arc<ArcSwap<AppConfig>>,
    deprecation_registry: DeprecationRegistry,
}

impl ConfigLoader {
    /// Initial load + validation. Fails on validation errors.
    pub fn load_initial(path: &Path) -> Result<(Self, Arc<ArcSwap<AppConfig>>), ConfigError>;

    /// Hot reload: parse, validate, swap atomically. Detects listener-shape changes
    /// and rejects them with a structured error (R-N5 carve-out).
    pub fn reload(&self) -> Result<ReloadOutcome, ConfigError>;
}

pub enum ReloadOutcome {
    Applied { changed_tools: Vec<String> },
    RejectedListenerShapeChange { details: String },
    NoChange,
}
```

**Loading pipeline:**
1. Read file → string.
2. Parse via `serde_yaml` with `deny_unknown_fields` enabled. Unknown fields → consult deprecation registry (INF-24); registered → log one-shot warning + apply rule; unregistered → reject with `ConfigError::UnknownField`.
3. Validate semantic invariants: every tool has a unique name; `auth_mode` ∈ {`bearer`, `mtls`, `both`}; `egress` ∈ {`direct`, `proxied`}; rate-limit thresholds positive; etc. Validation is exhaustive *before* any swap (INF-16).
4. For typed `SecretRef` and legacy `${VAR}` strings: parse but do NOT resolve at this layer (resolution happens at the `SecretBackend` layer).
5. **Listener-shape detection:** compare `listen.*` and `auth_mode` and `mtls.*` to the currently-active config. If any changed → return `RejectedListenerShapeChange` with the field and the value diff; current config remains active. Operator gets a structured error and must restart.
6. Otherwise → `ArcSwap::store(Arc::new(new_config))`.

**Deprecation registry** (INF-24):

```rust
pub struct DeprecationRegistry {
    entries: Vec<DeprecationEntry>,
    warned_once: DashSet<String>,  // (path, field) seen this process lifetime
}

pub enum DeprecationDisposition {
    Renamed { new_name: &'static str },
    Deprecated,
    Removed,
}

pub struct DeprecationEntry {
    pub field_path: &'static str,        // "tools[].cloud" or "telemetry"
    pub disposition: DeprecationDisposition,
    pub replacement: Option<&'static str>,
    pub since_version: &'static str,
    pub removal_target: Option<&'static str>,
}
```

Initial registry:
- `tools[].cloud` → renamed to `tools[].egress` (`true → proxied`, `false → direct`)
- `telemetry` → removed (was M0 dead code; OTel deferred)
- `tools[].auth.value` legacy `String` form → deprecated, replaced by typed `SecretRef`

*Traces to: UC-1, UC-13; R-F2, R-F13, R-F16, R-N5; INF-15, INF-16, INF-17, INF-23, INF-24.*

#### 4.2.21 C-19: MigrationRunner

**Type:** module
**Location:** `src/migrations.rs` + `migrations/` directory

Wraps `sqlx::migrate!()`. At startup:

1. Open SQLite connection pool with the INF-21 PRAGMAs applied (`journal_mode=WAL`, `synchronous=NORMAL`, `wal_autocheckpoint=1000`, `foreign_keys=ON`, `busy_timeout=5000`).
2. `sqlx::migrate!("./migrations").run(&pool).await?` — applies any pending migrations and updates `_sqlx_migrations` table.
3. Verify schema version matches the binary's expected version. Mismatch → fail-fast.

Migrations are SQL files in `migrations/`:

- `migrations/0001_init.sql` — create `agents`, `bootstrap_tokens`, `audit` tables; create indexes (M2)
- `migrations/0002_audit_indexes.sql` — additional indexes if needed (M3)
- ... future migrations as schema evolves

Forward-only by design (INF-11). Rollback is operator backup-restore.

*Traces to: R-F8, R-N1; INF-11; Q-5.*

#### 4.2.22 C-20: ShutdownCoordinator

**Type:** module
**Location:** `src/shutdown.rs`

```rust
pub struct ShutdownCoordinator {
    drain_window: Duration,
    listeners: Vec<ListenerHandle>,
    notify: Arc<tokio::sync::Notify>,
}

impl ShutdownCoordinator {
    /// Install signal handlers for SIGINT and SIGTERM.
    pub fn install(drain_window: Duration) -> Self;

    /// Block on shutdown; on signal, signal all listeners to stop accepting,
    /// wait up to `drain_window` for in-flight requests, then return.
    pub async fn await_shutdown(self);
}
```

Each listener is started via `axum::serve(...).with_graceful_shutdown(notify.notified())`. The coordinator waits on a tokio JoinSet collecting the listener tasks; if any one fails to drain in `drain_window`, the coordinator logs warning + exits (process shutdown will close FDs).

*Traces to: R-F12; INF-1.*

---

### 4.3 Layer View

The v2 architecture extends the M0 layered architecture (§3.3). New layers introduced: **Persistence** and **Repositories** (M2 onward); refined **Listener** layer to support multiple listeners.

#### 4.3.1 Layer Mapping

| Layer | Components | Responsibilities |
|-------|-----------|------------------|
| **Listener / Process bootstrap** | C-1, C-2, C-3, C-4, C-5, C-19, C-20 | TCP/UDS bind, signal handling, migration apply, listener-shape lifecycle |
| **Routing / Middleware** | (within listeners) | URL dispatch, rate-limit gate, authn gate, capacity admission |
| **Authentication** | C-6, C-7, C-16 | Resolve credentials → identities; constant-time semantics; rate-limit-aware |
| **Service / Business logic** | C-12, C-13 | Admin operations + proxy forwarding; transport-independent |
| **Repositories** | C-8, C-9, C-10 | Type-safe SQL access; concurrency semantics; class-aware retention |
| **Cross-cutting** | C-15, C-17, C-18, C-14, C-11 | Rate limiting, response controls, config, secret resolution, audit fan-out |
| **Persistence** | (sqlx pool + WAL SQLite + JSONL file) | Durable storage; canonical audit |

#### 4.3.2 Listener layer — design notes

**Conventions** (from M0): single `axum::Router` per listener; middleware applied at `Router::layer`; `tower-http::trace::TraceLayer` first.
**New in this design:** multiple listeners, each with its own router and its own middleware stack. Path-based bypasses (the M0-A2 antipattern) are gone — `/livez`/`/readyz`/`/version` live on the agent listener as separate routes that simply have no auth middleware applied.
**Integration points:** all listeners read `Arc<ArcSwap<AppConfig>>` for current configuration; all listeners share the rate limiter (C-15); all admin listeners share `AdminService` (C-12).

#### 4.3.3 Authentication layer — design notes

**Conventions:** middleware reads request, returns `Result<Identity, Response>` where the failure response is a structured 401/403/429 with the audit side-effect already recorded.
**New in this design:** `AgentAuthenticator` and `OperatorAuthenticator` are *separate* traits, used in different middleware stacks. Identities are stored in axum request extensions for downstream handlers to extract via `Extension<Agent>` / `Extension<Operator>`.
**Integration points:** `MtlsValidator` (C-16) feeds into the mTLS impl of `AgentAuthenticator`; `RateLimiter` (C-15) is consulted before authentication to bound DoS surface.

#### 4.3.4 Service layer — design notes

**Conventions:** business logic methods take typed inputs, return typed outputs, never touch HTTP or YAML.
**New in this design:** `AdminService` is *the* admin business logic; transport handlers are 5–15 line wrappers. `ProxyEngine` is the proxy business logic; it owns the per-tool client pool and the streaming-pass-through invariant.
**Integration points:** Service methods take repositories by reference (or by `Arc<dyn Repository>`) for testability with test doubles; production wiring uses concrete repository impls.

#### 4.3.5 Repository layer — design notes

**Conventions:** one repository per top-level entity (agents, bootstrap_tokens, audit). Methods are async; errors are typed (`RepoError` enum). Concurrency invariants are enforced via SQL constraints + WHERE-clause-as-CAS, not application-level locks.
**New in this design:** introduces SQLite + sqlx (was none in M0). Repositories own their queries; SQL doesn't leak into the service layer. Compile-time-checked queries via `sqlx::query!`/`query_as!` per Q-5.
**Integration points:** all repositories share a single `SqlitePool` configured via `MigrationRunner` (C-19). The pool is sized by `database.pool_size` (default 5; sufficient for SQLite's single-writer + reader-pool model).

#### 4.3.6 Cross-cutting layer — design notes

**Conventions:** these components don't fit cleanly into the listener-handler-service-repository stack. They're consulted from multiple layers.
**New in this design:** `RateLimiter` consulted from middleware (listener); `ResponseControls` consulted from `ProxyEngine` (service); `ConfigLoader` referenced by all components via `Arc<ArcSwap<AppConfig>>`; `SecretBackend` consulted from service layer (`ProxyEngine`, `AdminService`); `JsonlAuditSink` consulted from `AuditRepository`.
**Integration points:** `AppState` holds references to all cross-cutting components; listeners pull what they need via `axum::extract::State<Arc<AppState>>`.

#### 4.3.7 Persistence layer — design notes

**Conventions** (new): SQLite WAL mode (INF-21); `sqlx` for everything; migrations are forward-only checked-in source (INF-11).
**New in this design:** the layer is brand-new — M0 has no persistence. The schema is in §4.6.
**Integration points:** sqlx pool is created once at startup; passed by `Arc` to repositories; closed gracefully on shutdown.

---

### 4.4 Systemic / Platform Interfaces

#### 4.4.1 Interface Integration Summary

| Interface | Current state (§3) | Design changes | Priority |
|-----------|--------------------|----------------|----------|
| Logging | `tracing` + JSON subscriber | Per-component spans; structured log fields for credential paths must use `<redacted>` placeholder; one-shot deprecation warnings (INF-24) | P1 |
| Metrics | None | New: `/metrics` listener (C-5), opt-in; counter/gauge schema in §4.4.2 | P2 |
| Tracing (distributed) | `TelemetryConfig` dead struct in M0 | Removed via INF-24 deprecation registry; OTel deferred to post-v2 | — |
| Configuration | YAML + ArcSwap + `${VAR}` | C-18 ConfigLoader: typed `SecretRef`, deprecation registry, atomic-validate-then-swap, listener-shape carve-out | P1 |
| Authentication | Single static bearer | C-6 trait + bearer + mTLS impls; structured tokens; constant-time verify | P1 |
| Authorization | None | Per-agent allowlist/denylist, server-side enforced in C-13 and C-12 | P1 |
| TLS (outbound) | reqwest + rustls-tls | Unchanged; per-tool client pool (C-13) reuses TLS state | P1 |
| TLS (inbound, admin) | None | C-3 admin HTTPS + C-4 bootstrap-only listener (M4/M6) | P1 |
| Audit | None | C-10 SQLite + C-11 JSONL secondary sink | P1 |
| Health checks | `/health` (single) | C-1 hosts `/livez`, `/readyz`, `/version` | P1 |
| Process supervision | SIGINT only | C-20 SIGINT + SIGTERM + drain window | P1 |
| Egress / network | `cloud:` flag + optional egress proxy | `egress: direct \| proxied` (R-F13); per-tool reqwest client pool | P1 |
| Persistence | None | sqlx + SQLite WAL + migrations (M2) | P1 |
| Secret resolution | Pre-parse `${VAR}` expansion | `SecretBackend` trait + `EnvBackend` (M2); file-sealed (M5); typed `SecretRef` | P1 |
| Rate limiting | None | C-15 in-memory token-bucket + per-target failure counter | P1 |
| Filesystem permissions | None special | Admin UDS 0660 + group; sealed-secret file expects pre-decryption permissions (M5) | P1 |

#### 4.4.2 Logging

**Conventions:** all operational logs route through `tracing`. JSON subscriber in production; pretty-print in tests. Log levels: `TRACE` (per-request internals, off in prod), `DEBUG` (handler entry/exit), `INFO` (lifecycle events: startup, shutdown, hot reload), `WARN` (deprecation warnings, JSONL sink disabled, CRL refresh failure), `ERROR` (audit-write errors, secret-backend errors).

**Span discipline:** every request gets a `trace_id` (16-byte random, included in tracing span). The `trace_id` is logged at the span boundary, *not* in audit (audit identifies by `agent_public_id` and `id`). Cross-referencing logs ↔ audit is the operator's job via `agent_public_id` + timestamp window.

**Credential redaction:** any `Debug` impl on `SecretRef`, `SecretString`, `Agent.secret_hash`, etc. emits `<redacted>`. Structured field names containing the substring `secret`, `token`, `password`, or `credential` are filtered to `<redacted>` by a custom tracing layer (defense-in-depth).

**Failure mode:** if the JSON subscriber fails to write (stderr broken pipe), the process continues; logs are lost but operation is unaffected.

#### 4.4.3 Metrics (M3+, opt-in)

**Counter and gauge schema:**

| Metric name | Type | Labels | Source component | Notes |
|-------------|------|--------|------------------|-------|
| `proxy_requests_total` | counter | `tool`, `status_class`, `decision` | C-13 | one per proxied request |
| `proxy_request_latency_ms` | histogram | `tool`, `status_class` | C-13 | wall-clock latency |
| `proxy_streaming_active` | gauge | (none) | C-13 | current streaming count, global |
| `proxy_streaming_active_per_agent_max` | gauge | `agent_public_id` | C-13 | per-agent peak (for tuning) |
| `proxy_streaming_capacity_exceeded_total` | counter | `tool`, `scope` (`agent`\|`global`) | C-13 | INF-18 |
| `auth_requests_total` | counter | `outcome`, `auth_method`, `listener` | C-6, C-7 | |
| `rate_limited_total` | counter | `endpoint`, `scope` (`per_ip`\|`per_target`) | C-15 | |
| `audit_writes_total` | counter | `event_class` | C-10 | |
| `audit_write_errors_total` | counter | `error_kind` | C-10 | |
| `audit_write_queue_depth` | gauge | (none) | C-10 | always 0 in sync mode (INF-26) |
| `audit_jsonl_dropped_total` | counter | (none) | C-11 | |
| `audit_jsonl_disabled` | gauge | (none) | C-11 | 1 if startup-unreachable, else 0 |
| `secret_backend_resolve_failures_total` | counter | `kind`, `tool` | C-14 | |
| `secret_backend_degraded_tools` | gauge | (none) | C-14 | INF-4 |
| `mtls_crl_age_seconds` | gauge | (none) | C-16 | M6 |
| `mtls_crl_refresh_failures_total` | counter | (none) | C-16 | M6 |
| `config_reload_total` | counter | `outcome` (`applied`\|`rejected_listener_shape`\|`rejected_validation`) | C-18 | |
| `process_uptime_seconds` | gauge | (none) | (process bootstrap) | |

**Failure mode:** metrics are best-effort; a metrics-recorder failure does not affect request handling.

#### 4.4.4 Configuration

**Conventions:** YAML, single file path (default `/etc/locksmith/config.yaml`); operator-credentials at `operator_credentials_path` (separate file); secret-resolution via `SecretBackend`.

**Hot reload:** SIGHUP triggers `C-18 ConfigLoader.reload()`. Result is one of `Applied`, `RejectedListenerShapeChange`, `RejectedValidation`, `NoChange`. The operator gets a structured response via the `locksmith config reload` CLI; logs reflect the same.

**Listener-shape detection:** R-N5 carve-out. Fields requiring restart: `listen.*` (any field), `auth_mode`, `mtls.ca_bundle`, `mtls.crl.url`, `database.path`. Hot-reloadable: tool entries, rate-limit thresholds, audit retention, metrics enable/disable, drain window.

**Failure mode:** validation failure on reload → previous config retained; structured error logged + returned via CLI. Operator fixes the YAML and re-issues the reload.

#### 4.4.5 Authentication / Authorization

Already detailed in §5 Q6 (defense-in-depth) and §4.2.8 (C-6) / §4.2.9 (C-7) / §4.2.18 (C-16). Summary:

- **Layered:** filesystem (admin UDS), TLS (admin HTTPS, bootstrap-only), bearer/mTLS (all listeners as configured), per-target rate-limit on failures.
- **Audit-on-failure:** every authentication failure is audited (INF-13); every authorization denial is audited (in `ProxyEngine.forward` and `AdminService` methods).
- **Cleartext credentials** never persisted (R-N2), never logged (R-N4), zeroized on drop (R-N3); returned exactly once at registration/rotation (R-N4).

#### 4.4.6 Persistence

**Database:** SQLite, single file at `database.path`. WAL mode + tuned PRAGMAs (INF-21). Three sidecar files at runtime: `.db`, `.db-wal`, `.db-shm`. Backup is `sqlite3 .backup` against the live file (WAL-safe) or filesystem snapshot.

**Pool:** `sqlx::SqlitePool` sized at `database.pool_size` (default 5). SQLite's single-writer model means there's no benefit to a large pool for writes; readers can run in parallel.

**Failure modes:**
- DB file unreachable at startup (INF-2): fail-fast.
- DB file becomes unreachable at runtime (disk failure, fs unmount): every repository call returns `RepoError::DatabaseUnavailable` → handlers return 503; `/readyz` flips to red.
- Disk full: writes return errors; audit records and admin operations fail; agent traffic continues to flow but per-call audit fails (logged + counter, not request-blocking per C-10 contract).
- WAL file growth: bounded by autocheckpoint (1000 pages); `locksmith maintenance checkpoint` for manual TRUNCATE.

#### 4.4.7 Egress

**Conventions** (per R-F13, INF-15): `egress: direct` → reqwest client uses no proxy; `egress: proxied` → reqwest client configured with `egress_proxy` URL via HTTP CONNECT.

**Failure modes:**
- Proxy unreachable: 502 + structured `egress_proxy_failure` body + audit (INF-20).
- Proxy returns non-2xx CONNECT: same as above.
- TLS handshake failure to upstream: 502 + audit `event=upstream_tls_failure`.

#### 4.4.8 Process supervision and lifecycle

**Conventions:** systemd unit owns the process (M5 hardening directives). Locksmith handles SIGINT (interactive) and SIGTERM (systemd stop). SIGHUP triggers config reload.

**Drain semantics** (INF-1): on SIGTERM/SIGINT, all listeners stop accepting; in-flight requests get up to `shutdown.drain_window_seconds` (default 30s); on timeout, listeners are forcibly closed and process exits.

**Failure mode:** if the process panics, systemd restarts. Idempotency: the SQLite store has consistent state on every commit; a half-finished operation is rolled back when the process dies (transactional).

---

### 4.5 Key Interaction Sequences

Six load-bearing flows. Each illustrates one of: happy path; multi-component complexity; error/edge handling; security-sensitive auth; hot-reload; capacity admission.

#### Sequence 1: Bootstrap registration (UC-1, UC-5)

```
Operator (CLI)             C-2 UDS         C-12 AdminService    C-9 BootstrapRepo   C-8 AgentRepo    C-10 Audit
    |                        |                  |                    |                  |              |
    ├─ locksmith bootstrap  ─┤                  |                    |                  |              |
    │  mint                  │                  │                    │                  │              │
    │                        ├─ operator_auth ──┘                    │                  │              │
    │                        ├─ AdminService.mint_bootstrap_token ──►│                  │              │
    │                        │                  │                    ├─ INSERT row ─►   │              │
    │                        │                  │  ◄── (id, secret) ──┤                  │              │
    │  ◄── { token } ────────┘                  │                    │                  │              │
    │                                           ├─ audit  ─────────────────────────────────────────────►│
    │                                                                                                   │
    │  (operator hands token to deploy script)                                                          │
    │                                                                                                   │
Agent                      C-2 UDS or C-4   C-12                  C-9                  C-8           C-10
                           Bootstrap-only
    ├─ POST /admin/agent/  ─┤
    │  register             │
    │  + Authorization:     ├─ verify bootstrap   ─►│              |                  |              |
    │    Bearer lk_<id>.<s> │   token (no agent-auth)              │                  │              │
    │  + body { name, ... } │                  ├─ AdminService.register_agent ──►     │              │
    │                       │                  │                    │                  │              │
    │                       │                  │  TRANSACTION BEGIN │                  │              │
    │                       │                  ├─ consume(id, sec, agent_id=NULL) ──► │              │
    │                       │                  │                    │ atomic UPDATE   │              │
    │                       │                  │                    │ SET used_at=now │              │
    │                       │                  │                    │ WHERE used_at IS NULL          │
    │                       │                  │                    │ AND verify_ok                  │
    │                       │                  │  ◄── BootstrapScope ┤                                │
    │                       │                  │                    │                  │              │
    │                       │                  ├─ AgentRepo.create(name, scope.allowlist...) ►│       │
    │                       │                  │                                       ├─INSERT─►│   │
    │                       │                  │  ◄── (public_id, secret)──────────────┤         │   │
    │                       │                  │  TRANSACTION COMMIT                                  │
    │                       │                  ├─ audit event=agent_register ──────────────────────►│
    │  ◄── 200 { public_id,─┘                                                                         │
    │       token }                                                                                   │
    │                                                                                                 │
    │  ── REUSE ATTEMPT (someone replays the bootstrap token) ──                                      │
    │                                                                                                 │
    ├─ POST /admin/agent/   ─┤                                                                         │
    │  register (same token)│                                                                          │
    │                       │                  ├─ AdminService.register_agent ──►                     │
    │                       │                  │  TRANSACTION BEGIN │                                  │
    │                       │                  ├─ consume(id, sec, ...) ──►                            │
    │                       │                  │                    │ row found (id matches)           │
    │                       │                  │                    │ but used_at IS NOT NULL          │
    │                       │                  │  ◄── Err(InvalidCredential) ─┤                        │
    │                       │                  │  TRANSACTION ROLLBACK                                  │
    │                       │                  ├─ audit event=bootstrap_reuse_attempt ─────────────►│
    │                       │                  │   event_class=security                               │
    │  ◄── 401 invalid_  ───┘                                                                         │
    │       credential                                                                                 │
```

**Note on the failure path:** if the agent name conflicts with an existing agent (INF-10), the transaction in step 3 rolls back — the bootstrap token is *not* consumed, so the operator can fix the name and retry without minting a new bootstrap token.

#### Sequence 2: Streaming proxy with capacity admission (UC-6)

```
Agent                  C-1 Listener      C-6 AgentAuth    C-13 ProxyEngine     reqwest client    Anthropic       C-10 Audit
  |                       |                |                |                     |                |               |
  ├─ POST /api/anthropic/─┤                |                |                     |                |               |
  │  v1/messages          │                |                |                     |                |               |
  │  Authorization: Bearer├─ middleware ──►│                |                     |                |               |
  │  lk_<id>.<secret>     │                ├─ parse public_id, secret              |                |               |
  │  Accept: text/event-  │                ├─ AgentRepo.get_active_by_public_id()  |                |               |
  │  stream               │                ├─ argon2::verify_encoded               |                |               |
  │                       │                ├─ check revoked/expired               |                |               |
  │                       │                ├─ touch_last_used                     |                |               |
  │                       │  ◄── Agent ────┤                                       |                |               |
  │                       │                                |                       |                |               |
  │                       ├─ delegate to ProxyEngine ─────►│                       |                |               |
  │                       │                                │                       |                |               |
  │                       │                                ├─ tool ∈ allowlist? yes                 |               |
  │                       │                                │   ∉ denylist?       yes                |               |
  │                       │                                │   credential present? yes              |               |
  │                       │                                ├─ capacity.admit(public_id):           |               |
  │                       │                                │   per-agent count: 12 < 50 ✓          |               |
  │                       │                                │   global count:  847 < 1000 ✓         |               |
  │                       │                                │                       |                |               |
  │                       │                                ├─ get pooled client for "anthropic"     |               |
  │                       │                                │   (cache hit; warm TLS conn pool)      |               |
  │                       │                                │                       |                |               |
  │                       │                                ├─ resolve secret(SecretRef::FromEnv     |               |
  │                       │                                │   { var: "ANTHROPIC_API_KEY" })        |               |
  │                       │                                │  ◄── SecretString                      |               |
  │                       │                                │                       |                |               |
  │                       │                                ├─ build req: copy method, path, body, ─►│                |               |
  │                       │                                │   strip auth headers, inject           │                |               |
  │                       │                                │   x-api-key: <secret>                  │                |               |
  │                       │                                ├─ client.execute(req).await ───────────►├─ POST /v1/msg ►│               |
  │                       │                                │                       │                │                │               |
  │                       │                                │  ◄── Response (headers, byte_stream) ──┤                │               |
  │                       │                                │                       │                │                │               |
  │                       │                                ├─ wrap stream in Body::from_stream      │                │               |
  │  ◄── 200 OK ──────────┤  ◄── axum::Response ───────────┤   apply C-17 size cap                  │                │               |
  │  Content-Type: text/  │                                │                       │                │                │               |
  │  event-stream         │                                │                       │                │                │               |
  │                       │                                                                                          │               |
  │  ◄── data: {...}\n\n  ─────── chunks streamed (no buffering, R-N6 ≤100ms first-byte) ──────────────────────────  │               |
  │  ◄── data: {...}\n\n  ────────                                                                                                    │               |
  │  ◄── data: [DONE]\n\n ────────                                                                                                    │               |
  │                                                                                                                                   │               |
  │                       │                                ├─ stream end; capacity.release(public_id) (Drop guard fires)             │
  │                       │                                ├─ audit.record(event=proxy_request, event_class=proxy,                    │
  │                       │                                │    tool="anthropic", status=200, latency_ms=18432, decision=allowed) ─►│
```

**Capacity-exceeded path:** if step "capacity.admit" fails (per-agent at 50 or global at 1000), `ProxyEngine.forward` short-circuits to a `503 streaming_capacity_exceeded` response with `Retry-After: 1` and audit `event=streaming_capacity_exceeded`.

#### Sequence 3: Operator-initiated revocation (UC-4)

```
Operator (CLI)         C-2 UDS         C-7 OpAuth        C-12 AdminService    C-8 AgentRepo    C-10 Audit
    |                     |                |                  |                    |               |
    ├─ locksmith agent    ┤                |                  |                    |               |
    │  revoke <public_id> │                |                  |                    |               |
    │  --reason "suspect  │                |                  |                    |               |
    │     compromise"     │                |                  |                    |               |
    │                     ├─ middleware ──►│                  |                    |               |
    │                     │                ├─ parse op token ─┤                    |               |
    │                     │                ├─ verify          │                    |               |
    │                     │  ◄── Operator ─┤                  |                    |               |
    │                     ├─ delegate to AdminService ───────►│                    |               |
    │                     │                                   ├─ AgentRepo.revoke ►│               |
    │                     │                                   │                    ├─ UPDATE      │
    │                     │                                   │                    │ SET revoked_ │
    │                     │                                   │                    │ at=now WHERE │
    │                     │                                   │                    │ public_id=?  │
    │                     │                                   │  ◄── () ───────────┤               |
    │                     │                                   ├─ audit event=agent_revoke,         │
    │                     │  ◄── 204 ────────────────────────┤   event_class=operator,            │
    │  ◄── revoked        ┤                                   │   operator_name=alice,             │
    │     successfully    │                                   │   details={"reason":...}─────────►│
    │                                                                                              |
    │  ── now the suspect agent makes a request ──                                                |
    │                                                                                              |
Suspect Agent          C-1 Listener     C-6 AgentAuth                                              |
    ├─ POST /api/github/ ┤                |                                                       |
    │  ...               │                |                                                       |
    │  Authorization:    ├─ middleware ──►│                                                       |
    │  Bearer (revoked)  │                ├─ AgentRepo.get_active_by_public_id                     |
    │                    │                │   filters revoked_at IS NULL → returns None          |
    │                    │                │  Wait — actually we want to distinguish "missing"    |
    │                    │                │   from "revoked" for audit purposes. Use              |
    │                    │                │   .get_by_public_id(include_revoked=true) and check   |
    │                    │                │   revoked_at in code, so audit can record the actual  |
    │                    │                │   revocation reason.                                  |
    │                    │                ├─ AuthError::Revoked                                  |
    │                    │  ◄── 401 ──────┤                                                      |
    │                    │   invalid_     │                                                      |
    │                    │   credential   ├─ audit event=auth_failure event_class=security        |
    │  ◄── 401 ──────────┘                │   reason=revoked agent_public_id=<id> ──────────────►│
```

#### Sequence 4: Hot reload with rejection (R-N5, INF-16, INF-17)

```
Operator (CLI)        C-18 ConfigLoader      Active Config (ArcSwap)          listeners
    |                       |                       |                            |
    ├─ locksmith config    ─┤                       |                            |
    │  reload               │                       |                            |
    │                       ├─ read /etc/locksmith/config.yaml                   |
    │                       ├─ serde_yaml::from_str                              |
    │                       │                                                    |
    │                       ├─ ── Case A: unknown field ──                        |
    │                       │   field "extra_thingie" not in registry             |
    │                       │  ◄── ConfigError::UnknownField                      |
    │  ◄── error: unknown  ─┤                                                    |
    │     field at          │                                                    |
    │     path "..."        │                                                    |
    │                                                                            |
    │  ── operator fixes typo, re-issues reload ──                                |
    │                                                                            |
    ├─ locksmith config    ─┤                                                    |
    │  reload               │                                                    |
    │                       ├─ read + parse                                       |
    │                       │   field "tools[3].cloud" present                    |
    │                       │   in deprecation registry → renamed → egress:      |
    │                       │   one-shot warn (not yet warned this proc)         |
    │                       │                                                    |
    │                       ├─ semantic validation passes                          |
    │                       │                                                    |
    │                       ├─ listener-shape diff:                                |
    │                       │   listen.agent.port: 9200 → 9202 ✗ (changed)         |
    │                       │  ◄── ReloadOutcome::RejectedListenerShapeChange      |
    │  ◄── error: listener ─┤                                                    |
    │     shape change      │                                                    |
    │     requires restart  │                                                    |
    │     (listen.agent.port│                                                    |
    │      9200 → 9202)     │                                                    |
    │                                                                            |
    │  ── operator reverts the listener change, just bumps a tool's timeout ──    |
    │                                                                            |
    ├─ locksmith config    ─┤                                                    |
    │  reload               │                                                    |
    │                       ├─ read + parse + validate (deprecation warn          |
    │                       │   not re-emitted; warned_once is set)                |
    │                       │                                                    |
    │                       ├─ listener-shape diff: no changes                     |
    │                       │                                                    |
    │                       ├─ ArcSwap.store(new_config)  ────────────────────►   │
    │                       │                                                    ├─ all components see new
    │                       ├─ identify changed tools (tool "github" timeout)    │   config on next .load()
    │                       ├─ evict cached client for "github" from pool         │
    │                       ├─ audit event=config_reload outcome=applied          │
    │  ◄── reloaded ───────┤                                                    │
    │     (1 tool changed)  │                                                    │
```

#### Sequence 5: mTLS handshake with revocation check (UC-12, M6)

```
Agent (mTLS)        C-3 Admin HTTPS      rustls handshake     C-16 MtlsValidator    C-8 AgentRepo    C-10 Audit
    |                     |                    |                    |                    |               |
    ├─ TCP connect ──────►│                    |                    |                    |               |
    │                     ├─ TLS handshake ───►│                    |                    |               |
    │  ◄── server cert ──┤                    │                    |                    |               |
    │  ── client cert ───►│                    │                    |                    |               |
    │                     │                    ├─ standard TLS validation (rustls)       |               |
    │                     │                    │   chain to CA, expiration, signature    |               |
    │                     │  ◄── peer_cert ────┤                                          |               |
    │                     │                                                                |               |
    │                     ├─ MtlsValidator.validate(peer_cert) ─────►│                    |               |
    │                     │                                          ├─ x509-parser parse  |               |
    │                     │                                          ├─ check CRL          |               |
    │                     │                                          │   serial NOT in CRL ✓               |
    │                     │                                          ├─ check local       │               |
    │                     │                                          │   blocklist        │               |
    │                     │                                          │   serial NOT in blocklist ✓        |
    │                     │                                          ├─ extract CN ("agent-7")            |
    │                     │  ◄── MtlsIdentity { value: "agent-7" } ──┤                    |               |
    │                     │                                                                |               |
    │                     ├─ AgentRepo.get_by_cert_identity("agent-7") ──────────────────►│               |
    │                     │  ◄── AgentRecord ──────────────────────────────────────────────┤               |
    │                     │                                                                                |
    │                     ├─ middleware sets Extension<Agent>; route handler runs                          │
    │                     ├─ audit event=auth_success auth_method=mtls cert_serial=...─────────────────►│
    │                     │                                                                                |
    │  ── Now if cert is revoked between sessions and agent reconnects ──                                  |
    │                                                                                                      |
    ├─ TCP connect ──────►│                                                                                |
    │  TLS handshake (cert presents) ──►│                                                                  |
    │                     ├─ MtlsValidator.validate ────────────────►├─ check CRL                          |
    │                     │                                          │   serial IN CRL ✗                   |
    │                     │  ◄── MtlsError::Revoked ─────────────────┤                                     |
    │                     ├─ TLS connection terminated with alert; or HTTP 401 inside TLS                  |
    │                     ├─ audit event=auth_failure auth_method=mtls reason=revoked─────────────────►│
```

**CRL refresh failure handling:** if CRL fetch fails on a periodic refresh, the existing CRL stays in effect (stale). Validation continues. Operators monitor `mtls_crl_age_seconds` and `mtls_crl_refresh_failures_total` to detect this.

#### Sequence 6: Audit query (UC-8)

```
Operator (CLI)         C-2 UDS         C-7 OpAuth      C-12 AdminService    C-10 AuditRepo
    |                     |                |                |                    |
    ├─ locksmith audit    ┤                |                |                    |
    │  query --tool       │                |                |                    |
    │   github --since    │                |                |                    |
    │   30d --decision    │                |                |                    |
    │   denied            │                |                |                    |
    │                     ├─ middleware ──►│                |                    |
    │                     │  ◄── Operator ─┤                |                    |
    │                     ├─ delegate to AdminService.query_audit ─►│            |
    │                     │                                  ├─ AuditFilter { tool: "github",
    │                     │                                  │   since: now - 30d, decision: denied }
    │                     │                                  ├─ AuditRepo.query ►│
    │                     │                                  │                    ├─ SQL:
    │                     │                                  │                    │  SELECT ... FROM audit
    │                     │                                  │                    │  WHERE tool='github'
    │                     │                                  │                    │  AND ts >= ? AND
    │                     │                                  │                    │  decision='denied'
    │                     │                                  │                    │  ORDER BY ts DESC
    │                     │                                  │                    │  LIMIT 1000
    │                     │                                  │                    │  (uses idx (ts) and
    │                     │                                  │                    │   filter scan)
    │                     │                                  │  ◄── { rows[],     │
    │                     │                                  │      next_cursor } ┤
    │                     │  ◄── AuditQueryResult ─────────────┤                  |
    │                     │                                  ├─ audit event=admin_query        │
    │                     │                                  │   event_class=operator ────────►│
    │  ◄── table output  ─┤                                                                    |
    │     (or --format json)                                                                    |
```

---

### 4.6 Data Model Changes (Consolidated)

**Database:** SQLite, single file at `database.path` (default `/var/lib/locksmith/locksmith.db`). WAL mode + INF-21 PRAGMAs.

#### 4.6.1 Schema Tables

| Table | Change | Detail |
|-------|--------|--------|
| `agents` | **New table** (M2) | See §5 Q2; columns: `id`, `public_id`, `name`, `description`, `secret_hash`, `tool_allowlist`, `tool_denylist`, `metadata`, `cert_identity`, `registered_at`, `last_used_at`, `expires_at`, `revoked_at`, `role_id` |
| `bootstrap_tokens` | **New table** (M2) | See §5 Q2; columns: `id`, `public_id`, `secret_hash`, `scope`, `created_by`, `created_at`, `expires_at`, `used_at`, `used_by_agent_id`, `revoked_at` |
| `audit` | **New table** (M2 schema, populated from M3) | See §5 Q2; columns: `id`, `ts`, `schema_version`, `event_class`, `event`, `agent_public_id`, `operator_name`, `tool`, `upstream_host`, `method`, `path`, `status`, `latency_ms`, `decision`, `auth_method`, `origin_ip`, `details` |

#### 4.6.2 DDL — `migrations/0001_init.sql` (M2)

```sql
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA wal_autocheckpoint = 1000;
PRAGMA foreign_keys = ON;
PRAGMA busy_timeout = 5000;

CREATE TABLE agents (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    public_id       TEXT NOT NULL UNIQUE,
    name            TEXT NOT NULL UNIQUE,
    description     TEXT,
    secret_hash     TEXT NOT NULL,
    tool_allowlist  TEXT,
    tool_denylist   TEXT,
    metadata        TEXT,
    cert_identity   TEXT,
    registered_at   INTEGER NOT NULL,
    last_used_at    INTEGER,
    expires_at      INTEGER,
    revoked_at      INTEGER,
    role_id         INTEGER
);

CREATE INDEX idx_agents_active ON agents(public_id) WHERE revoked_at IS NULL;
CREATE INDEX idx_agents_cert_identity ON agents(cert_identity)
    WHERE cert_identity IS NOT NULL AND revoked_at IS NULL;

CREATE TABLE bootstrap_tokens (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    public_id          TEXT NOT NULL UNIQUE,
    secret_hash        TEXT NOT NULL,
    scope              TEXT NOT NULL,
    created_by         TEXT NOT NULL,
    created_at         INTEGER NOT NULL,
    expires_at         INTEGER,
    used_at            INTEGER,
    used_by_agent_id   INTEGER REFERENCES agents(id),
    revoked_at         INTEGER
);

CREATE INDEX idx_bootstrap_active ON bootstrap_tokens(public_id)
    WHERE used_at IS NULL AND revoked_at IS NULL;

CREATE TABLE audit (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    ts                 INTEGER NOT NULL,
    schema_version     INTEGER NOT NULL DEFAULT 1,
    event_class        TEXT NOT NULL CHECK (event_class IN ('proxy','operator','security')),
    event              TEXT NOT NULL,
    agent_public_id    TEXT,
    operator_name      TEXT,
    tool               TEXT,
    upstream_host      TEXT,
    method             TEXT,
    path               TEXT,
    status             INTEGER,
    latency_ms         INTEGER,
    decision           TEXT NOT NULL CHECK (decision IN ('allowed','denied','error')),
    auth_method        TEXT,
    origin_ip          TEXT,
    details            TEXT
);

CREATE INDEX idx_audit_ts ON audit(ts);
CREATE INDEX idx_audit_agent_ts ON audit(agent_public_id, ts) WHERE agent_public_id IS NOT NULL;
CREATE INDEX idx_audit_class_ts ON audit(event_class, ts);
CREATE INDEX idx_audit_tool_ts ON audit(tool, ts) WHERE tool IS NOT NULL;
```

**Constraint notes:**
- `agents.name UNIQUE` enforces INF-10 (one agent per name; concurrent register conflict).
- The partial index on `agents(public_id) WHERE revoked_at IS NULL` keeps the auth-path lookup pointed at active agents only.
- `audit.decision` and `audit.event_class` are CHECK-constrained to bound the value space — typo'd values fail at insert time, not at query time.
- `idx_audit_class_ts` supports the class-aware retention prune (INF-19).
- `idx_audit_tool_ts` supports UC-8's "calls to tool X over time window" query.

#### 4.6.3 Future Migrations (forward-only per INF-11)

| Migration | Milestone | Purpose |
|-----------|-----------|---------|
| `0002_audit_schema_v2.sql` | M3+ | Reserved for any schema_version bump (INF-12) |
| `0003_role_id_constraints.sql` | post-v2 | Activate `role_id` FK + constraints when fine-grained operator roles ship (D-6) |

### 4.7 UX Mocks

Locksmith has no graphical UI. Its operator-facing surface is three things:

1. The `locksmith` CLI (R-F9) — the canonical operator interface for every operator workflow in the PRD.
2. The YAML configuration files — `config.yaml` and `operators.yaml` — read at startup and on hot reload. The schema *is* the UX for deploy-time configuration.
3. The structured HTTP and CLI error responses — what an operator sees in `curl` or in the CLI when something fails.

This section documents the design of each surface.

#### 4.7.1 UX surface map

| Surface | Audience | Workflows |
|---------|----------|-----------|
| `locksmith` CLI | Human operators (interactively or via Ansible) | UC-1, UC-4, UC-5, UC-8, UC-10, UC-11 |
| YAML configs | Human operators (deploy time + hot reload) | UC-1, UC-9, UC-13 |
| HTTP responses | Agents (programmatic), operators (debugging via curl) | UC-2, UC-3, UC-6, UC-7, UC-12 |
| Audit output | Compliance reviewers (via operator) | UC-8 |

#### 4.7.2 Design conventions

**CLI:**
- Subcommand-style, hyphen-separated nouns then verbs (`locksmith agent revoke`, `locksmith bootstrap mint`).
- Short flags for the 2–3 most-used options per command; long flags for everything.
- Default output format: human-readable table for lists, key-value blocks for single records, plain text for action confirmations. `--format json` and `--format yaml` switch any output to machine-readable.
- Color (when stdout is a TTY): green for success, yellow for warnings, red for errors, dim for secondary information. `NO_COLOR=1` disables.
- Exit codes: 0 success, 1 generic error, 2 usage error, 3 auth error, 4 not-found, 5 conflict (e.g., name in use, rotation race).
- Cleartext credentials returned exactly once (R-N4) are emitted to stdout *only*, never to a log file, with a warning suffix that the value will not be shown again.

**YAML:**
- Two-space indent, snake_case keys.
- Comments above every non-trivial field in the example config explaining what it does and what the default is.
- `#` comment marks deprecated fields with a one-line description of the replacement; the loader still accepts them per INF-24.
- Field order in the example follows operator mental model: listeners → auth_mode → mtls → operator credentials → database → audit → shutdown → rate_limit → streaming → secret_backend_failure → egress_proxy → tools.

**Error messages:**
- Structured: a top-level `error` object with `code` (machine-readable enum), `message` (human-readable), `details` (object with field-specific data), and an optional `hint` (next-step guidance).
- The same `code` value is used in CLI exit, HTTP body, and audit `event`. A reviewer reading audit can grep for `bootstrap_reuse_attempt` and find both the security event and the operator's prior-failed CLI invocation.

#### 4.7.3 CLI command surface

```
$ locksmith --help

Agent Locksmith — credential and identity substrate for AI agents.

USAGE:
  locksmith [GLOBAL OPTIONS] <COMMAND>

GLOBAL OPTIONS:
  --socket <PATH>         Admin Unix socket (default: /run/locksmith/admin.sock)
  --token-env <VAR>       Read operator token from this env var (default: LOCKSMITH_OP_TOKEN)
  --format <FORMAT>       Output format: table | json | yaml (default: table)
  -v, --verbose           Increase log verbosity
  --no-color              Disable color output
  --help                  Show help

COMMANDS:
  agent          Manage agents
  bootstrap      Manage bootstrap tokens
  tool           List configured tools (operator)
  audit          Query and tail the audit log
  export         Export agent state as YAML for backup / inspection
  config         Reload or inspect daemon configuration
  maintenance    Operator maintenance: WAL checkpoint, audit pruning, etc.
  status         Show agent self-service status (requires agent token)
  rotate         Rotate the calling agent's token (requires agent token)
  bench          Run local benchmarks (auth, audit-write); used by M2/M3 tasks

Run `locksmith <command> --help` for details on a subcommand.
```

**Operator subcommands** (use `--token-env LOCKSMITH_OP_TOKEN` or default lookup):

```
$ locksmith agent --help

Manage agents.

USAGE:
  locksmith agent <SUBCOMMAND>

SUBCOMMANDS:
  list             List all agents (operator)
  get <ID|NAME>    Show one agent
  register         Operator-driven registration (no bootstrap token needed)
  modify <ID>      Update allowlist, denylist, metadata, expiration
  revoke <ID>      Revoke (soft-delete) an agent
```

```
$ locksmith bootstrap --help

Manage bootstrap tokens.

SUBCOMMANDS:
  mint           Mint a new bootstrap token
  list           List bootstrap tokens (active + used + revoked)
  revoke <ID>    Revoke an unused bootstrap token
```

#### 4.7.4 Sample CLI invocations

**Mint a bootstrap token (UC-5):**

```
$ locksmith bootstrap mint --allowlist anthropic,github --single-use --expires-in 24h

Bootstrap token minted.

  Public ID:    bt_a3X8Kj9mPq2RfL5t7wVz1Y
  Token:        bt_a3X8Kj9mPq2RfL5t7wVz1Y.eK9pR2sT4uV6wX8yZ0aB1cD2eF3gH4iJ5kL6mN7oP8qR9sT
  Expires:      2026-04-30 22:46:00 PDT (in 24h)
  Allowlist:    anthropic, github
  Single-use:   yes

⚠️  This token is shown ONCE. Save it now — it cannot be retrieved later.
```

**Register an agent via Ansible (UC-1):**

```
$ locksmith agent register \
    --name agent-7 \
    --description "openclaw-hardened agent on host-7" \
    --allowlist anthropic,github \
    --metadata '{"host":"host-7","deployed_by":"ansible"}'

Agent registered.

  Public ID:    ag_3K8Lm9NpQr2StUvWx5yZ7aB
  Name:         agent-7
  Token:        ag_3K8Lm9NpQr2StUvWx5yZ7aB.fL0qS3tUvW7xY9zA1bC2dE3fG4hI5jK6lM7nO8pQ9rS0tU
  Allowlist:    anthropic, github
  Denylist:     (none)
  Expires:      (no expiry)

⚠️  This token is shown ONCE. Save it now — it cannot be retrieved later.
```

**List agents (operator, default table format):**

```
$ locksmith agent list

PUBLIC ID                 NAME       STATUS    ALLOWLIST           LAST USED            REGISTERED
ag_3K8Lm9NpQr2StUvWx5y…   agent-7    active    anthropic,github    2026-04-29 22:14:03  2026-04-28 09:17:12
ag_pZ9MnQrSt4UvWx7yZ2a…   agent-12   active    (all)               2026-04-29 22:46:01  2026-04-15 11:03:44
ag_9YzAbCdEfGhIjKl3mNo…   agent-old  revoked   anthropic           2026-04-22 18:42:11  2026-04-01 14:00:00
                                      ↑ revoked 2026-04-22 19:01:00

3 agents (2 active, 1 revoked).
```

**JSON output for the same query:**

```
$ locksmith agent list --format json

{
  "agents": [
    {
      "public_id": "ag_3K8Lm9NpQr2StUvWx5yZ7aB",
      "name": "agent-7",
      "description": "openclaw-hardened agent on host-7",
      "status": "active",
      "tool_allowlist": ["anthropic", "github"],
      "tool_denylist": null,
      "metadata": {"host": "host-7", "deployed_by": "ansible"},
      "registered_at": "2026-04-28T09:17:12Z",
      "last_used_at": "2026-04-29T22:14:03Z",
      "expires_at": null,
      "revoked_at": null
    }
    // ...
  ]
}
```

**Get a single agent:**

```
$ locksmith agent get agent-7

Agent: agent-7

  Public ID:     ag_3K8Lm9NpQr2StUvWx5yZ7aB
  Description:   openclaw-hardened agent on host-7
  Status:        active
  Allowlist:     anthropic, github
  Denylist:      (none)
  Metadata:      {"host": "host-7", "deployed_by": "ansible"}
  Cert identity: (not set)
  Registered:    2026-04-28 09:17:12 (1d 13h ago)
  Last used:     2026-04-29 22:14:03 (32m ago)
  Expires:       (no expiry)

Recent audit (last 5 events):
  2026-04-29 22:14:03  proxy_request    anthropic  POST /v1/messages    200    1832ms  allowed
  2026-04-29 22:13:48  proxy_request    anthropic  POST /v1/messages    200    2104ms  allowed
  2026-04-29 22:13:01  proxy_request    github     GET /repos/...       200      87ms  allowed
  2026-04-29 22:08:14  proxy_request    anthropic  POST /v1/messages    200    1976ms  allowed
  2026-04-29 21:55:32  rotation                                                          (self-rotated)
```

**Revoke an agent (UC-4):**

```
$ locksmith agent revoke agent-7 --reason "suspect compromise; investigating"

✓ Agent agent-7 (ag_3K8Lm9NpQr2StUvWx5yZ7aB) revoked.

  Revoked at:   2026-04-29 22:46:15
  Reason:       suspect compromise; investigating

Subsequent requests with this agent's token will return 401.
Audit event: agent_revoke (id 184729).
```

**Self-service rotate (UC-2; agent calls; via the agent's token in env):**

```
$ LOCKSMITH_AGENT_TOKEN=<current> locksmith rotate

✓ Token rotated.

  Public ID:    ag_3K8Lm9NpQr2StUvWx5yZ7aB
  New token:    ag_3K8Lm9NpQr2StUvWx5yZ7aB.gM1rT4uVwX8yZ0aB2cD3eF4gH5iJ6kL7mN8oP9qR0sT1uV

⚠️  This token is shown ONCE. Save it now — it cannot be retrieved later.

Note: the previous token is now invalid (D-13). All in-flight requests on the old token will return 401.
```

**Self-service status (UC-3):**

```
$ LOCKSMITH_AGENT_TOKEN=<token> locksmith status

Agent: agent-7

  Public ID:    ag_3K8Lm9NpQr2StUvWx5yZ7aB
  Status:       active
  Allowlist:    anthropic, github
  Denylist:     (none)
  Tools available to me:
    - anthropic    https://api.anthropic.com    (egress: proxied)
    - github       https://api.github.com       (egress: proxied)
  Expires:      (no expiry)
  Registered:   2026-04-28 09:17:12
  Last used:    2026-04-29 22:46:00
```

#### 4.7.5 Multi-step operator workflows

**Workflow A — Onboard a new agent via Ansible (UC-1):**

```
Step 1 — Operator runs (locally or in CI):
$ locksmith bootstrap mint --allowlist anthropic,github --single-use --expires-in 1h
  → outputs cleartext bootstrap token

Step 2 — Token is written to Ansible vault, distributed with the playbook.

Step 3 — On the target host, the playbook runs:
$ locksmith agent register \
    --bootstrap-token "$BOOTSTRAP_TOKEN_FROM_VAULT" \
    --name "agent-$(hostname)" \
    --description "..."
  → outputs cleartext agent token

Step 4 — Playbook writes agent token into the agent process's config:
        e.g., /etc/openclaw/agent.env: LOCKSMITH_AGENT_TOKEN="ag_..."

Step 5 — Playbook starts (or reloads) the agent process.

Step 6 — Agent boots, reads its token, calls Locksmith /admin/agent/status to verify.
```

**Workflow B — Rotation (UC-2):**

```
Agent code (pseudocode):
  if token_age > rotation_threshold:
      response = locksmith.rotate(current_token)
      if response.status == 200:
          atomic_write_secret_file(response.token)  # zero-downtime rotation
          current_token = response.token
      elif response.status == 409:
          # Another rotate raced us (INF-9). Try again later.
          schedule_retry(seconds=60)

CLI equivalent for diagnostic / operator-driven:
$ locksmith rotate --token-from /etc/openclaw/agent.env
```

**Workflow C — Compromise response (UC-4):**

```
Step 1 — Detect: operator notices anomalous traffic in audit log.
$ locksmith audit query --agent agent-7 --since 1h --decision denied
  → review denied calls

Step 2 — Revoke immediately:
$ locksmith agent revoke agent-7 --reason "anomalous traffic detected"

Step 3 — Verify revocation:
$ locksmith agent get agent-7
  → status: revoked

Step 4 — Audit subsequent denial:
$ locksmith audit query --agent agent-7 --since 1h
  → see auth_failure events recorded after revocation

Step 5 — If replacing: mint a new bootstrap token under a new identity (D-12):
$ locksmith bootstrap mint --allowlist <subset> --single-use
  → re-onboard as agent-7-replacement (NOT the same name; D-12)
```

#### 4.7.6 Audit query output

**Default table:**

```
$ locksmith audit query --tool github --since 7d --decision denied --limit 10

TIMESTAMP            CLASS    EVENT             AGENT            TOOL    METHOD  PATH                STATUS  LATENCY  DECISION
2026-04-29 19:34:12  security auth_failure      ag_pZ9MnQ…      github  -       -                   -       -        denied
2026-04-29 14:17:03  proxy    proxy_request     ag_pZ9MnQ…      github  POST    /repos/.../issues   403     142ms    denied
2026-04-28 22:11:55  proxy    proxy_request     ag_3K8Lm9…      github  GET     /user                403       3ms    denied
2026-04-27 08:42:18  security auth_failure      (unknown)       -       -       -                   -       -        denied
2026-04-25 11:05:09  security bootstrap_reuse_  -                -       -       -                   -       -        denied
                              attempt

5 events. Use --cursor=<cursor> to fetch more (or --no-paginate).
```

**JSON output:**

```
$ locksmith audit query --tool github --since 7d --format json

{
  "events": [
    {
      "id": 184729,
      "ts": "2026-04-29T19:34:12.184Z",
      "schema_version": 1,
      "event_class": "security",
      "event": "auth_failure",
      "agent_public_id": "ag_pZ9MnQrSt4UvWx7yZ2a",
      "operator_name": null,
      "tool": null,
      "upstream_host": null,
      "method": null,
      "path": null,
      "status": null,
      "latency_ms": null,
      "decision": "denied",
      "auth_method": "bearer",
      "origin_ip": "10.0.0.42",
      "details": { "reason": "revoked" }
    }
    // ...
  ],
  "next_cursor": "eyJ0c19sdF9pZCI6Wy4uLl19",
  "total_estimate": 5
}
```

**Tail (real-time follow):**

```
$ locksmith audit tail --tool anthropic

[2026-04-29 22:46:18] proxy   proxy_request     ag_3K8Lm9…  anthropic  POST /v1/messages  200  1832ms  allowed
[2026-04-29 22:46:23] proxy   proxy_request     ag_3K8Lm9…  anthropic  POST /v1/messages  200  2104ms  allowed
[2026-04-29 22:46:31] proxy   proxy_request     ag_pZ9MnQ…  anthropic  POST /v1/messages  200  1976ms  allowed
^C
```

#### 4.7.7 Configuration UX (YAML-as-interface)

The annotated `config.example.yaml` shipped with v2 (M1+ as fields land):

```yaml
# Agent Locksmith configuration. See docs/v2/SPEC.md §4.7.7 for field reference.

# ── Listeners ───────────────────────────────────────────────────────────
listen:
  agent:
    host: "0.0.0.0"           # bind address; 127.0.0.1 for localhost-only
    port: 9200                # default 9200

  # Admin Unix socket. Local operator interface.
  admin_socket:
    path: "/run/locksmith/admin.sock"
    mode: 0o660               # filesystem permission (octal)
    group: "locksmith"        # OS group; operators must be in this group

  # Admin HTTPS listener. Off by default. Enable for remote management (UC-11).
  admin_https:
    enabled: false
    host: "127.0.0.1"
    port: 9201
    tls:
      cert_file: "/etc/locksmith/admin.crt"
      key_file: "/etc/locksmith/admin.key"

  # Bootstrap-only listener for mtls-only deployments (Q-3 / PRD §14.1 #3).
  # Off by default. Lock down with network policy when enabled.
  bootstrap:
    enabled: false
    host: "127.0.0.1"
    port: 9202
    tls:
      cert_file: "..."
      key_file: "..."

  # Prometheus metrics. Off by default.
  metrics:
    enabled: false
    port: 9091

# ── Authentication ──────────────────────────────────────────────────────
auth_mode: "bearer"              # "bearer" | "mtls" | "both" (M6)

# mTLS configuration. Required when auth_mode is "mtls" or "both" (M6).
# mtls:
#   ca_bundle: "/etc/locksmith/ca.pem"
#   identity_field: "CN"          # or "SAN:DNS", "SAN:URI"
#   crl:
#     url: "https://ca.example.com/crl.pem"
#     refresh_interval_seconds: 3600
#   blocklist_path: "/etc/locksmith/mtls-blocklist.txt"

# ── Operator credentials ────────────────────────────────────────────────
# Path to operators YAML file. Records have argon2-hashed tokens (Q-4).
operator_credentials_path: "/etc/locksmith/operators.yaml"

# ── Persistence ─────────────────────────────────────────────────────────
database:
  path: "/var/lib/locksmith/locksmith.db"

# ── Audit ───────────────────────────────────────────────────────────────
audit:
  proxy_retention_days: 90       # high-volume class (Q-23)
  operator_retention_days: 365   # operator and security events
  row_count_cap: 10000000        # safety net (INF-19)
  jsonl:
    enabled: false
    path: "/var/log/locksmith/audit.jsonl"
    required: false              # if true, refuse to start when sink unreachable

# ── Lifecycle ───────────────────────────────────────────────────────────
shutdown:
  drain_window_seconds: 30       # in-flight request drain on SIGTERM (INF-1)

# ── Rate limits ────────────────────────────────────────────────────────
rate_limit:
  register: { per_ip_per_minute: 60 }
  rotate:   { per_ip_per_minute: 60, per_target_failures_per_5min: 10 }
  operator: { per_ip_per_minute: 60, per_target_failures_per_5min: 10 }

# ── Streaming concurrency ──────────────────────────────────────────────
streaming:
  global_concurrency_cap: 1000   # process-wide ceiling (INF-18)
  per_agent_concurrency_cap: 50  # per-agent fairness floor

# ── Secret backend behavior ────────────────────────────────────────────
secret_backend_failure: "fail-fast"   # "fail-fast" (default) | "degraded"

# ── Egress ─────────────────────────────────────────────────────────────
# HTTP CONNECT proxy URL used for tools with egress: proxied (typically Pipelock).
egress_proxy: "http://127.0.0.1:8888"

# ── Tools ──────────────────────────────────────────────────────────────
tools:
  - name: "anthropic"
    description: "Anthropic Messages API"
    upstream: "https://api.anthropic.com"
    egress: "proxied"            # "direct" | "proxied" (R-F13)
    auth:
      header: "x-api-key"
      value: { from_env: "ANTHROPIC_API_KEY" }    # typed SecretRef (INF-23)
    timeouts:
      request_seconds: 600       # multi-minute generations
      idle_seconds: 600
    body_limit_bytes: 10485760   # 10 MiB
    response:
      max_size_bytes: 10485760
      content_type_allowlist: ["application/json", "text/event-stream"]
      redaction_patterns: []
    # on_secret_failure: degraded   # optional per-tool override (INF-4)

  - name: "lmstudio"
    upstream: "http://localhost:1234"
    egress: "direct"
    timeouts: { request_seconds: 600, idle_seconds: 600 }

  # Legacy field names (cloud:, telemetry:) still accepted with one-shot warning
  # via the deprecation registry (INF-24). Migrate at your convenience.
```

The annotated `operators.yaml`:

```yaml
# Operator credentials. Filesystem-only; never in the database (R-N10).
# Owner-only readable; loaded at startup, reloaded on file change.

operators:
  - name: "alice"
    # argon2id hash of the operator's cleartext token.
    # Generate with: locksmith bench hash-operator-token
    token_hash: "$argon2id$v=19$m=4096,t=3,p=1$..."
    scope: null   # reserved for future fine-grained operator roles (D-6)

  - name: "ansible"
    token_hash: "$argon2id$v=19$m=4096,t=3,p=1$..."
```

#### 4.7.8 Configuration error message UX

**Unknown field:**

```
$ locksmith config reload

✗ Configuration reload failed.

  Error code:    config_unknown_field
  At path:       tools[2].extra_thingie
  Field value:   "ignored"
  Hint:          This field is not recognized. Check for typos. If you intended
                 to use a deprecated field, see the migration table at:
                 docs/v2/SPEC.md §4.2.20 (deprecation registry).

The previous configuration remains active.
```

**Listener-shape change rejected:**

```
$ locksmith config reload

✗ Configuration reload requires restart.

  Error code:    config_listener_shape_change
  Field:         listen.agent.port
  Was:           9200
  Now:           9202
  Hint:          Listener-shape changes (port, address, TLS cert paths,
                 auth_mode, mtls.*) cannot be applied without restarting
                 Locksmith. The R-N5 hot-reload guarantee covers tool entries,
                 rate limits, audit retention, and metrics — not listener
                 shape.

To apply: restart the Locksmith service.
The previous configuration remains active.
```

**Deprecation warning (one-shot):**

```
$ locksmith config reload

⚠ Deprecation: tools[3].cloud
  This field is being renamed.
  Disposition:   renamed → tools[3].egress
  Mapping:       cloud: true  → egress: proxied
                 cloud: false → egress: direct
  Since version: 0.2.0
  Will be removed in: 0.3.0

✓ Configuration reloaded.
  Changed tools: github
  Reload outcome: applied
```

#### 4.7.9 HTTP error response shapes (operator-visible via curl)

All error responses share a single envelope. Operators debugging the agent path with `curl -v` see consistent shapes.

**401 missing/invalid credential:**

```
$ curl -i -H "Authorization: Bearer lk_abc.invalid" \
       http://localhost:9200/api/anthropic/v1/messages

HTTP/1.1 401 Unauthorized
Content-Type: application/json
WWW-Authenticate: Bearer realm="locksmith"

{
  "error": {
    "code": "invalid_credential",
    "message": "Authentication failed.",
    "details": {}
  }
}
```

**403 tool not allowed:**

```
HTTP/1.1 403 Forbidden
Content-Type: application/json

{
  "error": {
    "code": "tool_not_allowed",
    "message": "Agent agent-7 is not allowed to call tool github.",
    "details": {
      "agent_public_id": "ag_3K8Lm9...",
      "tool": "github",
      "reason": "tool_not_in_allowlist"
    },
    "hint": "Operator can grant access via: locksmith agent modify ag_3K8Lm9... --add-allowlist github"
  }
}
```

**409 rotation in progress:**

```
HTTP/1.1 409 Conflict
Content-Type: application/json

{
  "error": {
    "code": "rotation_in_progress",
    "message": "Another rotate call for this agent is in progress.",
    "details": {},
    "hint": "Retry with the previous credential; if the previous credential has been replaced, the prior rotate succeeded — use the new credential."
  }
}
```

**409 agent name conflict:**

```
HTTP/1.1 409 Conflict
Content-Type: application/json

{
  "error": {
    "code": "agent_name_conflict",
    "message": "An agent with name 'agent-7' already exists.",
    "details": { "name": "agent-7" },
    "hint": "Choose a different name or revoke the existing agent first. Note: the bootstrap token was NOT consumed; you can retry with a different name."
  }
}
```

**429 rate limited:**

```
HTTP/1.1 429 Too Many Requests
Content-Type: application/json
Retry-After: 60

{
  "error": {
    "code": "rate_limited",
    "message": "Too many requests from this origin.",
    "details": {
      "endpoint": "/admin/agent/register",
      "retry_after_seconds": 60
    }
  }
}
```

**502 egress proxy failure (Pipelock unreachable):**

```
HTTP/1.1 502 Bad Gateway
Content-Type: application/json

{
  "error": {
    "code": "egress_proxy_failure",
    "message": "Egress proxy failed for tool 'anthropic'.",
    "details": {
      "tool": "anthropic",
      "phase": "connect",
      "underlying": "connection refused"
    },
    "hint": "Check that the configured egress_proxy is reachable. The proxy URL itself is not exposed in this response for security reasons."
  }
}
```

**503 streaming capacity exceeded:**

```
HTTP/1.1 503 Service Unavailable
Content-Type: application/json
Retry-After: 1

{
  "error": {
    "code": "streaming_capacity_exceeded",
    "message": "Concurrent streaming request limit reached.",
    "details": {
      "scope": "per_agent",
      "current": 50,
      "limit": 50
    },
    "hint": "Reduce concurrent streaming calls or ask your operator to raise streaming.per_agent_concurrency_cap."
  }
}
```

**503 secret-backend degraded (tool unavailable):**

```
HTTP/1.1 503 Service Unavailable
Content-Type: application/json

{
  "error": {
    "code": "tool_credential_unavailable",
    "message": "Tool 'experimental-llm' is configured for degraded-mode operation and its credential is currently unresolved.",
    "details": { "tool": "experimental-llm" },
    "hint": "Operator can resolve by setting the configured environment variable or sealed-secret file and reloading config."
  }
}
```

#### 4.7.10 State variations

For each operator-facing list output (CLI):

| State | CLI display | Source |
|-------|-------------|--------|
| Empty | `No agents registered.` (table); `{"agents":[]}` (JSON) | DB returns 0 rows |
| Single result | one-row table or single-record key-value block | DB returns 1 row |
| Paginated | table + `<N> events. Use --cursor=<C> to fetch more.` footer | result set > `--limit` |
| Filtered to zero | `No agents match the filter (status=revoked,name~=foo).` | filter applied, 0 rows |
| Backend error | `✗ Could not contact daemon at <socket>: <reason>.` | UDS connect failure |
| Auth error | `✗ Authentication failed (code: invalid_credential). Check $LOCKSMITH_OP_TOKEN.` | 401 from daemon |
| Permission denied (UDS) | `✗ Permission denied: cannot connect to /run/locksmith/admin.sock. Are you in the 'locksmith' group?` | OS-level EACCES |
| Audit-only retention | `(no events in window)` | retention pruned older events |

#### 4.7.11 What is intentionally not in v2

- **Web UI / dashboard.** Deferred per PRD §13. The CLI + HTTP admin API cover all capability; UI is a usability layer that can lag and possibly live as a sibling project.
- **Interactive TUI** (cursor-based menus). Not needed for an admin tool driven primarily by Ansible / scripts.
- **Local operator-token autogeneration UX** (a `locksmith operator init` that mints + writes `operators.yaml`). The current path is `locksmith bench hash-operator-token` to compute the hash, operator manually edits the YAML. This is sufficient for v2; a UX improvement for v3.

---

## 5. Design Questions FAQ

### Q1: Main components and interactions

See §3.3 (M0 layered architecture) and §3.13 (M0→v2 responsibility migration) for the baseline. The v2 design adds the following components on top of M0; full component decomposition with boundaries and dependencies lands in §4.2.

**Listener-shape components (process-level, M1/M2/M4/M6):**

- **C-1: Agent listener** (existing TCP listener). Hosts agent proxy traffic on `/api/{tool}/{*path}`, agent-self-service admin on `/admin/agent/*` (M2 over Unix socket only; M4 also exposes over HTTPS), and `/healthz`/`/readyz`/`/version` (INF-3) and `GET /tools` (R-F6, UC-7). Auth middleware enforces `AgentAuthenticator` (D-7).
- **C-2: Admin Unix socket** (M2). Hosts both `/admin/agent/*` and `/admin/operator/*` over a UDS at `/run/locksmith/admin.sock` (mode 0660, group `locksmith`, INF-7). The CLI (R-F9) is the canonical client.
- **C-3: Admin HTTPS listener** (M4, optional, off-by-default). Same `/admin/{agent,operator}/*` namespaces over HTTPS on a separate port for remote management (UC-11, R-F10). Bearer auth in M4; mTLS as second auth method in M6.
- **C-4: Bootstrap-only listener** (M6, optional). Server-TLS (no client mTLS required) accepting only `POST /admin/agent/register` with a bootstrap token; resolves Q-3 / PRD §14.1 #3 in mtls-only deployments.
- **C-5: Metrics listener** (M3+, opt-in). Prometheus text-format `/metrics` on a separate port (INF-14, Q-19).

**Service / business-logic components (M2..M7):**

- **C-6: `AgentAuthenticator` trait + bearer impl** (M2). Takes a request, returns an authenticated `Agent` record. Bearer impl uses structured tokens `lk_<public_id>.<secret>` (INF-5). mTLS impl follows in M6.
- **C-7: `OperatorAuthenticator`** (M2). Same shape as C-6 but resolves operator credentials from operator-only YAML config (R-N10). Per-operator argon2-hashed tokens (Q-4 / PRD §14.1 #4).
- **C-8: `AgentRepository`** (M2). SQLite-backed CRUD for agent records: `register`, `get_by_public_id`, `update_allowlist`, `revoke` (soft-delete via `revoked_at`), `list`. Uses `sqlx` (Q-5).
- **C-9: `BootstrapTokenRepository`** (M2). Mint, list, revoke, consume. `consume` is transactional and atomic — first call succeeds; subsequent calls return `consumed`. Bootstrap-token reuse is a security event (INF-13, Q-8).
- **C-10: `AuditRepository`** (M3). Writes to SQLite `audit` table (schema in §4.6). Optional sink fan-out to `JsonlAuditSink`. Class-aware retention worker (INF-19, Q-23).
- **C-11: `JsonlAuditSink`** (M3, optional). Bounded mpsc channel (default 10k) with drop-newest back-pressure (PRD §14.1 #6). Daily rotation + 100MB cap; `audit-YYYYMMDD.jsonl`. Non-fatal on startup-unreachable by default (INF-22, Q-21).
- **C-12: `AdminService`** (M2). Pure business logic for admin operations. Both the Unix-socket router (C-2) and the HTTPS router (C-3) call into the same `AdminService` so behavior is identical across transports.
- **C-13: `ProxyEngine`** (M1 streaming + M3 audit + M7 controls). Wraps the existing M0 `proxy_handler`. Streams via `Body::from_stream(reqwest::Response::bytes_stream(...))`; per-tool reqwest client pool (INF-25, Q-27); per-tool body/timeout/response controls (R-F12, R-F15); writes audit on completion (R-F7).
- **C-14: `SecretBackend` trait + `EnvBackend`** (M2 with INF-23). Resolves a `SecretRef` to a `SecretString`. Env-var impl ships in M2 alongside the typed `SecretRef` schema (INF-23). File-sealed and Vault/AWS impls land in M5 (R-F17).
- **C-15: `RateLimiter`** (M2). In-memory token-bucket (per-IP) and per-target-id failure counter (INF-6, Q-15). Applied to `register`, `rotate`, and operator endpoints.
- **C-16: `MtlsValidator`** (M6). Validates client certs against configured CA bundle, checks expiration, consults CRL fetcher and local emergency blocklist (Q-10 / PRD §14.1 #10). Extracts identity from CN or configurable SAN (R-F16).
- **C-17: `ResponseControls`** (M7). Per-tool max response size, content-type allowlist, optional regex redaction (R-F15). Streaming responses subject only to total-size cap.

**Infrastructure / cross-cutting (process-wide):**

- **C-18: `ConfigLoader`** (M2 evolution of M0 `config::load_config`). Field-scoped `${VAR}` expansion (INF-23 deprecated path) plus typed `SecretRef` parsing; `deny_unknown_fields` with deprecated-fields registry (INF-24); atomic reload via ArcSwap (M0-A1, R-N5, INF-16) with full validation before swap; restart-required carve-out for listener-shape changes (R-N5 amended).
- **C-19: `MigrationRunner`** (M2). Embedded `sqlx::migrate!()` invocation at startup. Forward-only (INF-11). Migration files in `migrations/`.
- **C-20: `ShutdownCoordinator`** (M1). Listens on SIGINT and SIGTERM, signals all listeners to stop accepting, waits up to a configurable drain window (default 30s) for in-flight requests, then closes (INF-1).

**Key new interaction flows** (full sequences in §4.5):

- **Bootstrap registration:** Operator mints bootstrap token via CLI → `AdminService.mint_bootstrap_token` → `BootstrapTokenRepository`. Agent calls `POST /admin/agent/register` with bootstrap token → `BootstrapTokenRepository.consume` (atomic) → `AgentRepository.create` → return cleartext agent token (returned exactly once, R-N4) → audit.
- **Streaming proxy:** Agent calls `/api/anthropic/v1/messages` → C-1 agent listener → `AgentAuthenticator.authenticate` → C-13 `ProxyEngine.forward` → reqwest streaming response → axum `Body::from_stream` → SSE chunks pass through ≤100ms first-byte added (R-N6) → audit on completion.
- **Operator audit query:** Operator runs `locksmith audit query --tool github --since 30d` → CLI opens UDS to C-2 → `OperatorAuthenticator.authenticate` → `AdminService.query_audit` → `AuditRepository.query` → CLI prints structured output (UC-8).

### Q2: Core API contracts and data models

#### Data model (M2 SQLite schema)

The schema below is sketched here per the kickoff prompt's "domain modeling explicit and early" requirement. Final DDL ships as `migrations/0001_init.sql` in M2; the `audit` table column shape lands in M2 but its writes happen in M3.

**Table `agents`**

| Column | Type | Notes |
|--------|------|-------|
| `id` | INTEGER PRIMARY KEY AUTOINCREMENT | Internal numeric id |
| `public_id` | TEXT UNIQUE NOT NULL | URL-safe 128-bit token public-id half (INF-5) |
| `name` | TEXT UNIQUE NOT NULL | Operator-assigned identifier |
| `description` | TEXT | Free-text; nullable |
| `secret_hash` | TEXT NOT NULL | argon2id hash of token secret half |
| `tool_allowlist` | TEXT | JSON array; NULL = all tools |
| `tool_denylist` | TEXT | JSON array; NULL = none |
| `metadata` | TEXT | JSON object; opaque |
| `cert_identity` | TEXT | CN or SAN value when authed via mTLS (M6); nullable |
| `registered_at` | INTEGER NOT NULL | Unix seconds |
| `last_used_at` | INTEGER | Unix seconds; nullable until first use |
| `expires_at` | INTEGER | Unix seconds; nullable = no expiry |
| `revoked_at` | INTEGER | Unix seconds; nullable; soft-delete (D-12) |
| `role_id` | INTEGER | Reserved for future fine-grained operator roles (D-6) |

Indexes: `(public_id)` UNIQUE, `(name)` UNIQUE, `(revoked_at)` partial index where `revoked_at IS NULL`.

**Table `bootstrap_tokens`**

| Column | Type | Notes |
|--------|------|-------|
| `id` | INTEGER PRIMARY KEY AUTOINCREMENT | |
| `public_id` | TEXT UNIQUE NOT NULL | |
| `secret_hash` | TEXT NOT NULL | argon2id |
| `scope` | TEXT NOT NULL | JSON: `{ tool_allowlist, expires_at, single_use }` |
| `created_by` | TEXT NOT NULL | Operator name (for audit) |
| `created_at` | INTEGER NOT NULL | |
| `expires_at` | INTEGER | nullable |
| `used_at` | INTEGER | nullable |
| `used_by_agent_id` | INTEGER | FK → `agents.id`; nullable |
| `revoked_at` | INTEGER | nullable; soft-delete |

**Table `audit`** (created in M2, populated from M3)

| Column | Type | Notes |
|--------|------|-------|
| `id` | INTEGER PRIMARY KEY AUTOINCREMENT | |
| `ts` | INTEGER NOT NULL | Unix milliseconds |
| `schema_version` | INTEGER NOT NULL | INF-12 |
| `event_class` | TEXT NOT NULL | `proxy` \| `operator` \| `security` (INF-19, Q-23) |
| `event` | TEXT NOT NULL | e.g., `proxy_request`, `agent_register`, `auth_failure`, `rotation`, `bootstrap_reuse_attempt`, `egress_proxy_failure` |
| `agent_public_id` | TEXT | nullable (operator events have no agent) |
| `operator_name` | TEXT | nullable (proxy events have no operator) |
| `tool` | TEXT | nullable |
| `upstream_host` | TEXT | nullable |
| `method` | TEXT | nullable |
| `path` | TEXT | nullable |
| `status` | INTEGER | nullable |
| `latency_ms` | INTEGER | nullable |
| `decision` | TEXT NOT NULL | `allowed` \| `denied` \| `error` |
| `auth_method` | TEXT | `bearer` \| `mtls` \| `bootstrap` \| `operator`; nullable |
| `origin_ip` | TEXT | nullable |
| `details` | TEXT | JSON; reason codes, redaction flags, etc. |

Indexes: `(ts)`, `(agent_public_id, ts)`, `(event_class, ts)`. The third index supports class-aware retention pruning (INF-19).

#### YAML configuration shape (consolidated, M1 + M2 + later)

```yaml
listen:
  agent:                                   # C-1
    host: "0.0.0.0"
    port: 9200
  admin_socket:                            # C-2 (M2)
    path: "/run/locksmith/admin.sock"
    mode: 0o660
    group: "locksmith"
  admin_https:                             # C-3 (M4, optional)
    enabled: false
    host: "127.0.0.1"
    port: 9201
    tls:
      cert_file: "/etc/locksmith/admin.crt"
      key_file: "/etc/locksmith/admin.key"
  bootstrap:                               # C-4 (M6, optional)
    enabled: false
    host: "127.0.0.1"
    port: 9202
    tls: { cert_file: "...", key_file: "..." }
  metrics:                                 # C-5 (M3+, optional)
    enabled: false
    port: 9091

auth_mode: "bearer"                        # bearer | mtls | both (R-F16, M6)
mtls:                                      # M6
  ca_bundle: "/etc/locksmith/ca.pem"
  identity_field: "CN"                     # or "SAN:DNS", "SAN:URI"
  crl:
    url: "https://ca.example.com/crl.pem"
    refresh_interval_seconds: 3600
  blocklist_path: "/etc/locksmith/mtls-blocklist.txt"

operator_credentials_path: "/etc/locksmith/operators.yaml"   # R-N10, Q-4
database:
  path: "/var/lib/locksmith/locksmith.db"  # SQLite file
  pragmas:
    journal_mode: "WAL"
    synchronous: "NORMAL"
    wal_autocheckpoint: 1000               # INF-21

audit:
  proxy_retention_days: 90                 # Q-23
  operator_retention_days: 365             # Q-23
  row_count_cap: 10_000_000                # INF-19
  jsonl:
    enabled: false
    path: "/var/log/locksmith/audit.jsonl"
    required: false                        # INF-22, Q-21

shutdown:
  drain_window_seconds: 30                 # INF-1

rate_limit:                                # INF-6, Q-15
  register: { per_ip_per_minute: 60 }
  rotate:   { per_ip_per_minute: 60, per_target_failures_per_5min: 10 }
  operator: { per_ip_per_minute: 60, per_target_failures_per_5min: 10 }

streaming:                                 # INF-18, Q-22
  global_concurrency_cap: 1000
  per_agent_concurrency_cap: 50

secret_backend_failure: "fail-fast"        # INF-4, Q-17

egress_proxy: "http://127.0.0.1:8888"      # used when egress: proxied

tools:
  - name: "github"
    description: "GitHub REST API"
    upstream: "https://api.github.com"
    egress: "proxied"                      # R-F13, INF-15 (cloud: shim)
    auth:
      header: "Authorization"
      value: { from_env: "GITHUB_TOKEN", prefix: "Bearer " }   # INF-23 typed form
    timeouts:
      request_seconds: 30                  # R-F12
      idle_seconds: 60
    body_limit_bytes: 10_485_760           # R-F12
    response:                              # R-F15, M7
      max_size_bytes: 10_485_760
      content_type_allowlist: ["application/json"]
      redaction_patterns: []
    on_secret_failure: null                # null | degraded; INF-4

  - name: "anthropic"
    upstream: "https://api.anthropic.com"
    egress: "proxied"
    auth:
      header: "x-api-key"
      value: { from_env: "ANTHROPIC_API_KEY" }
    timeouts:
      request_seconds: 600                 # multi-minute generation
      idle_seconds: 600
    body_limit_bytes: 10_485_760

  - name: "lmstudio"
    upstream: "http://localhost:1234"
    egress: "direct"
    timeouts: { request_seconds: 600, idle_seconds: 600 }
```

`operator_credentials_path` content:

```yaml
operators:
  - name: "alice"
    token_hash: "$argon2id$v=19$m=4096,t=3,p=1$..."
    scope: null                            # reserved (D-6)
  - name: "ansible"
    token_hash: "$argon2id$v=19$m=4096,t=3,p=1$..."
```

#### New API endpoints

**Agent self-service (R-F4) — both Unix socket (M2) and HTTPS (M4):**

| Method | Endpoint | Body | Response | Auth |
|--------|----------|------|----------|------|
| `POST` | `/admin/agent/register` | `{ bootstrap_token, name, description?, metadata? }` | 200 `{ public_id, token, expires_at?, allowlist }`; 401 `invalid_credential`; 409 `agent_name_conflict` | Bootstrap token |
| `GET` | `/admin/agent/status` | — | 200 `{ public_id, name, allowlist, denylist, expires_at, registered_at, last_used_at }` | Agent token |
| `POST` | `/admin/agent/rotate` | — | 200 `{ public_id, token, expires_at? }`; 409 `rotation_in_progress` | Agent token |
| `POST` | `/admin/agent/deregister` | — | 204 | Agent token |

**Operator (R-F5):**

| Method | Endpoint | Body | Response | Auth |
|--------|----------|------|----------|------|
| `GET` | `/admin/operator/agents` | — | 200 `{ agents: [...] }` | Operator |
| `GET` | `/admin/operator/agents/{public_id}` | — | 200 `{ agent }`; 404 | Operator |
| `POST` | `/admin/operator/agents` | `{ name, description?, allowlist?, denylist?, metadata?, expires_at? }` | 200 `{ public_id, token, ... }` | Operator |
| `PATCH` | `/admin/operator/agents/{public_id}` | `{ allowlist?, denylist?, metadata?, expires_at? }` | 200 `{ agent }` | Operator |
| `POST` | `/admin/operator/agents/{public_id}/revoke` | — | 204 | Operator |
| `POST` | `/admin/operator/bootstrap_tokens` | `{ scope: { tool_allowlist?, expires_at?, single_use } }` | 200 `{ public_id, token, scope }` | Operator |
| `GET` | `/admin/operator/bootstrap_tokens` | — | 200 `{ tokens: [...] }` (no cleartext) | Operator |
| `POST` | `/admin/operator/bootstrap_tokens/{public_id}/revoke` | — | 204 | Operator |
| `GET` | `/admin/operator/tools` | — | 200 `{ tools: [...] }` (all configured, regardless of any agent's allowlist; UC-7 corollary) | Operator |
| `GET` | `/admin/operator/audit` | query: `since`, `until`, `agent`, `tool`, `event_class`, `event`, `decision` | 200 `{ events: [...], next_cursor }` | Operator |
| `GET` | `/admin/operator/export/agents` | query: `format=yaml` | 200 YAML body, no cleartext | Operator |

**Agent listener (existing, evolved):**

| Method | Endpoint | Notes |
|--------|----------|-------|
| `ANY` | `/api/{tool}/{*path}` | Streams (M1); audit on completion (M3); response controls (M7) |
| `GET` | `/tools` | Filtered per-agent by allowlist/denylist/credential-present (R-F6) |
| `GET` | `/livez` | Always 200 unless process broken (INF-3) |
| `GET` | `/readyz` | 200 when DB reachable + listener bound + required backends resolved |
| `GET` | `/version` | `{ version, commit_sha, build_date }` |

#### Key interaction flows (full sequences in §4.5)

**Flow: Bootstrap registration**
1. Operator: `locksmith bootstrap mint --allowlist github,anthropic --single-use`.
2. CLI opens UDS to C-2; `OperatorAuthenticator` verifies operator token; `AdminService.mint_bootstrap_token` writes row to `bootstrap_tokens`; CLI prints cleartext token.
3. Operator hands token to deploy script (or pastes into Ansible vault).
4. Agent: `POST /admin/agent/register` with `Authorization: Bearer <bootstrap>` + `{ name: "agent-7", ... }`.
5. C-2 router → `AdminService.register_agent`:
   - `BootstrapTokenRepository.consume(bootstrap)` (atomic UPDATE setting `used_at` and `used_by_agent_id` only when `used_at IS NULL`); failure on already-consumed → 401 `invalid_credential` + audit `bootstrap_reuse_attempt`.
   - `AgentRepository.create({ name, ... })`; UNIQUE-constraint failure on `name` → 409 `agent_name_conflict` and `BootstrapTokenRepository.consume` is rolled back (INF-10).
   - Generate `lk_<public_id>.<secret>`; argon2-hash the secret; store; return cleartext exactly once (R-N4).
6. Audit: `event=agent_register`, `event_class=operator` (since the operator caused the registration), `agent_public_id=<new>`.

**Flow: Streaming proxy**
1. Agent: `POST /api/anthropic/v1/messages` with bearer agent token.
2. C-1 agent listener → `AgentAuthenticator.authenticate(req)`:
   - Parse `Authorization: Bearer lk_<id>.<secret>`. Lookup `agents` row by `public_id` (timing-safe). Constant-time argon2-verify the secret. Return `Agent`.
3. Authorization: tool `anthropic` ∈ allowlist (and ∉ denylist). Yes → continue.
4. Capacity: `streaming.per_agent_concurrency_cap` and `streaming.global_concurrency_cap` checked (INF-18). Either at threshold → 503 `streaming_capacity_exceeded` + audit.
5. C-13 `ProxyEngine.forward`:
   - Get pooled `reqwest::Client` for `anthropic` (INF-25); build request (method, headers minus inbound-auth-related, body); inject `x-api-key: <secret>` from `SecretBackend`.
   - `client.send().await` returns headers; convert to axum response with `Body::from_stream(resp.bytes_stream())` (R-N6).
6. SSE chunks proxy through. Stream ends; latency captured from start to last byte; audit `event=proxy_request`, `event_class=proxy`, status, latency, etc.

**Flow: Audit query**
1. Operator: `locksmith audit query --tool github --since 30d --decision denied`.
2. CLI builds JSON query; opens UDS to C-2; `OperatorAuthenticator` verifies; `AdminService.query_audit` → `AuditRepository.query`:
   - SQL: `SELECT ... FROM audit WHERE tool='github' AND ts >= ? AND decision='denied' ORDER BY ts DESC LIMIT 1000`.
3. Returns paginated results with `next_cursor` for pages beyond 1000.
4. CLI formats as table (default), JSON (`--format json`), or CSV (`--format csv`).

### Q3: Deployment and infrastructure dependencies

Locksmith remains a single Rust binary plus a SQLite file (R-N1). v2 introduces no new external services that operators must run.

**Existing infrastructure relied on:**

- **Linux host with systemd** (typical deployment target). `openclaw-hardened` ships an Ansible role; this role gains tasks for: SQLite file directory creation, operator-credentials YAML path, operators-group provisioning, optional CRL fetch path (M6), optional sealed-secret backend file path (M5).
- **Ansible** (UC-1). The playbook is the canonical operator client during deploy; calls Locksmith's admin interface (UDS via local exec, or HTTPS via M4 if remote).
- **Optional Pipelock** for `egress: proxied` tools (D-16).

**New Locksmith-internal infrastructure:**

- **SQLite file** (`/var/lib/locksmith/locksmith.db` typical). Three sidecar files in WAL mode: `.db`, `.db-wal`, `.db-shm`. Write workload: one row per proxied request (M3) + admin operations. Read workload: one auth lookup per request. INF-21 PRAGMAs apply (Q-16). Backup is a `sqlite3 .backup` against the live DB or a filesystem snapshot — both safe under WAL.
- **Optional JSONL audit sink** (`/var/log/locksmith/audit.jsonl`). Operator typically tails this into Loki, Splunk, or Vector. Daily file rotation + 100MB cap (PRD §14.1 #6).
- **Optional metrics scrape target** on a separate port (default 9091). Prometheus pull (Q-19).
- **Optional CRL endpoint** (M6) reachable over the network for cert-revocation refresh.

**Configuration changes to existing infrastructure:**

- **systemd unit** (M5 hardening): `NoNewPrivileges=true`, `ProtectSystem=strict`, `PrivateTmp=true`, `ReadWritePaths=/var/lib/locksmith /var/log/locksmith /run/locksmith`, dedicated `locksmith` user/group, `BindPaths=/etc/locksmith` read-only.
- **Operator-group provisioning**: operators added to the `locksmith` group on the host so they can connect to the admin UDS (INF-7).
- **Reverse proxy** (only if M4 admin HTTPS is enabled and exposed publicly): operators may front the admin listener with nginx or Caddy for additional rate-limiting, ACL, or Tailscale-only exposure. Locksmith does not require this; the admin HTTPS listener is bind-address-configurable.

**Scaling considerations:**

- **Single-instance by design.** Locksmith is one process per host. There is no multi-instance HA story in v2 (rate limiter is in-memory, INF-6; ArcSwap is process-local). For the audiences in PRD §3 (hardened operators, homelab/small-team, Kamiwaza enterprise), this is sufficient — Locksmith is per-deployment, not a fleet-wide service. Multi-instance HA is a deferred concern (recorded as a future risk in Q7).
- **SQLite throughput.** WAL mode + `synchronous=NORMAL` supports ~10k writes/sec on commodity SSD. Audit-write rate at proxied-request volume (a typical agent does <100 calls/sec) sits well below this. Periodic `wal_checkpoint(TRUNCATE)` (`locksmith maintenance checkpoint`) keeps the WAL file from growing unbounded (INF-21).
- **Streaming concurrency.** Per-agent and global caps (INF-18, Q-22) are the operator's lever. Default 50/1000 is sized for typical hardware (Linux default fd limits are 1024 or 65535; 1000 streaming responses leaves headroom).
- **Connection pooling.** Per-tool reqwest client (INF-25) reuses TCP/TLS connections to upstreams within the connection pool defaults. Hot upstreams (Anthropic, OpenAI) reuse keep-alive across requests; cold upstreams pay one-time TLS handshake.

**What a platform engineer needs to provision:**

1. A Linux host (single instance per deployment).
2. The `locksmith` binary in `/usr/local/bin/`.
3. A `locksmith` system user and group; operator user accounts added to the `locksmith` group.
4. Three directories under `/var`: `lib/locksmith` (DB), `log/locksmith` (JSONL sink if used), `/run/locksmith` (admin socket; tmpfs is fine).
5. `/etc/locksmith/config.yaml` and `/etc/locksmith/operators.yaml`.
6. The systemd unit, the optional sealed-secret CRL paths.

### Q4: External components and interfaces

Locksmith's external surface is deliberately narrow:

- **Upstream HTTP services** (one per tool entry; existing). Locksmith is an HTTP client; injects credentials per `auth.header`/`auth.value`; forwards everything else byte-for-byte. New in v2: streaming response handling (M1), per-tool body and timeout caps (M1), HTTP CONNECT proxy invocation when `egress: proxied` (M1, R-F13). No special integration code; new upstreams are config-only (D-17).
- **Pipelock** (peer, optional). Interface: HTTP CONNECT proxy URL configured as `egress_proxy`. Locksmith opens a CONNECT tunnel for `egress: proxied` tools; Pipelock authorizes the destination. Pipelock cannot see credentials (Locksmith injects them inside the TLS-terminated upstream connection, D-16). Failure handling: 502 Bad Gateway with `egress_proxy_failure` audit event (INF-20).
- **Cognitive scanners (LlamaFirewall, NeMo Guardrails, etc.)** (peer, in agent process). No interface; D-18 says these compose with Locksmith in parallel, not in series. Locksmith is unaware of their presence. *Not* an external dependency.
- **Inference platforms (Kamiwaza, LiteLLM proxy, vLLM, TGI)** (peer, optional). Treated as ordinary tool entries. Whether they exist is the operator's choice; Locksmith does not require any inference platform. New in v2: streaming through these works (M1).
- **External CA** (M6, optional). For mTLS deployments, the operator runs a CA (smallstep, step-ca, internal PKI). Locksmith pulls the CA bundle from a configured file path; CRL via configured URL with periodic refresh (Q-10). Locksmith is *not* its own CA (PRD §M6 out-of-scope).
- **Sealed-secret tooling** (M5, optional). For the file-sealed `SecretBackend`, the operator uses `systemd-creds`, `sd-creds`, or equivalent to encrypt the upstream credential file at deploy time. Locksmith decrypts at startup using a key from the host's TPM or systemd's credential store. Interface: a file path; the encryption tooling is the operator's choice.
- **Log shipper (Loki, Splunk, Vector, Filebeat)** (peer, optional). For the JSONL audit sink. The shipper tails `audit.jsonl`; Locksmith writes; rotation handled by Locksmith. Interface: file system path, file rotation conventions, schema (mirror SQLite columns per PRD §14.1 #6).
- **Prometheus scraper** (M3+, optional). For metrics. Interface: HTTP pull on the configured port, Prometheus text-format exposition. Standard.

**No new integrations** in v2 require Locksmith-specific SDKs from peer tools. Locksmith remains agent-platform-agnostic and peer-tool-agnostic by design (R-N8, D-14, D-17, D-18).

### Q5: Testing strategy

**Unit tests** (`src/**/tests` modules):

| Component | Key scenarios |
|-----------|---------------|
| `ConfigLoader` (C-18) | Defaults; field-scoped `${VAR}` expansion; typed `SecretRef` parsing; `deny_unknown_fields` behavior; deprecated-fields registry (INF-24); listener-shape change detection on hot-reload (R-N5) |
| `AgentAuthenticator` bearer impl (C-6) | Token parsing for `lk_<id>.<secret>` shape; argon2-verify; revoked-agent rejection; expired-agent rejection; constant-time semantics (INF-5) |
| `OperatorAuthenticator` (C-7) | Per-operator argon2-verify; missing operators file → fail-fast |
| `AgentRepository` (C-8) | Concurrent register with same name → exactly-one-success (INF-10); revoke is soft-delete; allowlist/denylist enforcement |
| `BootstrapTokenRepository` (C-9) | `consume` is atomic; second consume → 401; `single_use=false` permits multi-use |
| `RateLimiter` (C-15) | Token-bucket refill; per-target-failure counter; bucket eviction |
| `AuditRepository` (C-10) | Class-aware retention pruning; row-count cap; index usage on common queries |
| `JsonlAuditSink` (C-11) | Drop-newest under back-pressure; rotation at size cap; rotation at day boundary; startup-unreachable non-fatal default |
| `MtlsValidator` (C-16) | CN extraction; SAN DNS extraction; SAN URI extraction; CRL hit; local-blocklist hit; expired cert; untrusted CA |
| `ResponseControls` (C-17) | Size cap on non-streaming; content-type rejection; redaction regex application; streaming subject only to total-size cap |
| `ProxyEngine` (C-13) | Header stripping; credential injection; per-tool client pooling; egress-proxy invocation; structured `egress_proxy_failure` (INF-20) |

**Integration tests** (`tests/`):

The M1 first failing test is the load-bearing test for the v2 effort. Per PRD §kickoff "Suggested order of attack":

| Test file | Coverage |
|-----------|----------|
| `tests/streaming_passthrough_test.rs` (M1, NEW) | Run a fixture upstream that emits SSE chunks at known intervals; assert chunks arrive at the test client within `upstream_first_byte + 100ms` (R-N6); assert long-running (>5min simulated) generations complete |
| `tests/inference_matrix_local_test.rs` (M1, NEW) | Fixture upstream serving OpenAI-compatible streaming response; Ollama if `OLLAMA_HOST` reachable; LM Studio if `LMSTUDIO_HOST` reachable. Run by default in CI |
| `tests/inference_matrix_cloud_test.rs` (M1, NEW) | Real Anthropic, OpenAI when `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` present. **Local-only per Q-2** — skipped in CI; run by engineers pre-PR |
| `tests/admin_socket_test.rs` (M2, NEW) | UDS bind/connect; mode 0660 enforcement; operator-credential check over the socket (INF-7) |
| `tests/agent_lifecycle_test.rs` (M2, NEW) | Bootstrap mint → consume → register → status → rotate → revoke; UC-1, UC-2, UC-3, UC-4, UC-5, UC-7 demonstrable end-to-end |
| `tests/concurrent_rotate_test.rs` (M2, NEW) | Two simultaneous `rotate` calls → 1 success, 1 409 (INF-9, Q-20) |
| `tests/concurrent_register_test.rs` (M2, NEW) | Two simultaneous registers with same name → 1 success, 1 409, bootstrap *not* consumed for failed call (INF-10) |
| `tests/audit_query_test.rs` (M3, NEW) | Mock 30 days of audit rows; UC-8 query returns expected aggregate |
| `tests/audit_jsonl_backpressure_test.rs` (M3, NEW) | Slow consumer → `audit_jsonl_dropped_total` counter increments; SQLite write succeeds (PRD §14.1 #6) |
| `tests/admin_https_test.rs` (M4, NEW) | TLS handshake; same admin operations available on UDS and HTTPS produce identical results |
| `tests/secret_backend_test.rs` (M5, NEW) | Env backend; file-sealed backend; degraded-mode tool surface (INF-4) |
| `tests/mtls_test.rs` (M6, NEW) | `bearer`, `mtls`, `both` modes; CRL revocation; local-blocklist revocation; expired cert; SAN identity extraction (UC-12) |
| `tests/response_controls_test.rs` (M7, NEW) | Size cap; content-type rejection; redaction; streaming preserved |

Existing M0 tests (`auth_test.rs`, `config_test.rs`, `discovery_test.rs`, `env_expansion_test.rs`, `health_test.rs`, `integration_test.rs`, `proxy_test.rs`, `tool_activation_test.rs`) are kept; expanded for the new fields and behaviors as each milestone lands.

**E2E tests:**

UC-9 (composed with Pipelock) and UC-12 (mTLS-authenticated agent end-to-end) are the two E2E flows that justify a multi-process test harness. Both run only locally, gated on env vars (Q-2 policy):

- `tests/e2e_pipelock_compose_test.rs` (M1+, run when `PIPELOCK_TEST_HOST` set): start Pipelock fixture, point `egress_proxy:` at it, verify `egress: proxied` traffic transits, `egress: direct` does not.
- `tests/e2e_mtls_full_test.rs` (M6, run when `MTLS_TEST_CA_DIR` set): mint a CA + agent cert via `rcgen`, configure Locksmith with `auth_mode: mtls`, agent presents cert, full auth flow including CRL refresh.

**Test infrastructure:**

- `wiremock` (already a dev-dep) — for fixture upstreams.
- `axum-test` (already a dev-dep) — for the integration test client.
- `rcgen` (new dev-dep, M6) — for minting test CAs and certs.
- `tempfile` (new dev-dep, M2) — for ephemeral SQLite files in tests.
- `serial_test` (new dev-dep, M2) — for tests that touch process-wide singletons (e.g., env vars under field-scoped `${VAR}` expansion).

**Verification matrix coverage check:** UC-1..UC-13 are each covered by at least one integration or E2E test. The traceability matrix in §4.1 enforces this once Phase 5 runs.

### Q6: Security implications

**Authentication layers:**

1. **Listener-boundary** (M2 onward). Each listener (agent TCP, admin UDS, admin HTTPS, bootstrap-only TLS, metrics) has its own middleware stack. The agent listener requires an agent token (or mTLS cert in M6); the admin UDS requires a connection inside the `locksmith` group *and* a valid operator token (INF-7); the admin HTTPS requires either bearer or mTLS depending on `auth_mode`; the bootstrap-only listener requires only a bootstrap token. No path-based bypass (replaces M0-A2).
2. **Token verification** (INF-5). Structured tokens `lk_<public_id>.<secret>`; lookup by public id (non-secret, timing-safe); argon2id-verify the secret. Constant-time at the secret comparison. Argon2 parameters per Q-13.
3. **Operator credentials** in operator-only YAML config (R-N10, Q-4). Per-operator named tokens, argon2-hashed in file. Not in DB — recoverable when DB is corrupted/wiped.
4. **mTLS** (M6, optional). Cert validates against CA bundle, expiration enforced, CRL + local blocklist consulted (Q-10). CN or configurable SAN field maps to agent record. Audit records `auth_method: mtls`.

**Authorization layers:**

1. **Endpoint scope** (D-3). Agent-self-service endpoints accept *no* path parameter for "which agent" — the caller is always the subject. Cross-agent operations only on `/admin/operator/*` namespace.
2. **Operator-credential gate** on operator endpoints. v1 operator credentials are all-or-nothing (D-6). Reserved `scope` field on operator record for future fine-grained roles.
3. **Per-agent allowlist/denylist** (R-F6). Tool discovery and proxy invocation both filter by `(allowlist == null OR tool ∈ allowlist) AND tool ∉ denylist AND credential_present`. Enforced server-side, audited on denial.
4. **Tool-credential presence check** (R-F6 corollary). Even an allowlisted tool is hidden if its `SecretBackend` has not resolved a credential. INF-4 / Q-17 makes this explicit.

**Defense-in-depth layers (the Locksmith threat model):**

| Layer | Defense | Defeated by |
|-------|---------|-------------|
| **Filesystem** | Admin UDS mode 0660, group `locksmith`. Operators-yaml owner-readable. `secret_backend_failure: fail-fast` default | Compromise of the locksmith user or root |
| **Token** | argon2id-hashed at rest (R-N2); cleartext returned exactly once (R-N4); zeroized on drop (R-N3); structured tokens with constant-time secret verify (INF-5) | Compromise of in-memory state during a token's lifetime |
| **Authentication** | Per-listener middleware; bearer or mTLS (M6); rate-limited (INF-6, Q-15) | Stolen valid token within its lifetime |
| **Authorization** | Per-agent allowlist/denylist; operator credentials separate from agent credentials | Misconfigured allowlist; compromised operator credential |
| **Audit** | Every credentialed call recorded; auth failures recorded as security events (INF-13); class-aware retention (INF-19) | Audit log tampering — no tamper-evidence in v2 (deferred per PRD §13) |
| **Egress** | Per-tool egress flag; Pipelock (D-16) for internet-bound | Compromise of an `egress: direct` LAN destination |
| **Network** | Admin HTTPS off-by-default; bootstrap-only listener for mtls onboarding | Mis-bound admin listener exposed publicly |
| **OS** | systemd hardening directives (M5) | Kernel exploit |

**Data isolation:**

- **Per-agent** boundaries. An agent token has access only to the calling agent's record; `/admin/agent/*` paths take no agent identifier. Tool discovery is scoped by allowlist/denylist. Each agent is its own scope.
- **Operator vs agent** boundaries. Operator credentials live in operator-only YAML; agent credentials live in SQLite. Operator endpoints take no agent token; agent endpoints take no operator token. The two namespaces never share a credential.
- **Tool-credential isolation.** Each tool has its own `SecretRef`. Compromise of a single upstream credential does not expose other tools.
- **Multi-tenancy.** Locksmith does not have a tenant abstraction. The deployment unit is the host. Multi-tenant isolation is a future concern (deferred per PRD §13).

**Header / token integrity:**

- Inbound `Authorization` and tool-specific auth headers (`x-api-key`, etc.) are stripped from forwarded requests (existing M0 behavior, kept). The only credential the upstream sees is the one Locksmith injects.
- Bootstrap tokens grant only `register`. They cannot be used for any other operation, regardless of `auth_mode` (D-10).

**Sensitive data handling:**

- All credentials wrapped in `secrecy::SecretString` from parse to use (R-N3).
- `Debug` impl on credential-bearing types must not print the secret (compile-time test in M2: a manual `Debug` impl with `<redacted>` placeholder).
- No credential value in logs, audit records, error responses, or API responses (R-N4).
- Cleartext returned exactly once at registration / rotation, never thereafter (R-N4).

**Threat model in scope for v2:**

- Compromised agent process attempts to escalate privileges → blocked by per-agent scope, allowlist enforcement, audit.
- Stolen bootstrap token → bounded by single-use semantics, expiration, rate limiting, security-event audit on reuse attempts.
- Operator-credential leak → operator can mint and revoke; mitigation is operator-credential rotation + monitoring; `mtls` for operators (M6, D-9) reduces this risk.
- Eavesdropping on admin traffic → admin UDS is local-only; admin HTTPS requires TLS; mTLS (M6) hardens further.
- Side-channel timing attack on token verification → mitigated by structured tokens + argon2-verify (INF-5).

**Out of scope for v2** (recorded in PRD §13):

- Audit-log tamper evidence (signing, append-only chains).
- Multi-tenant isolation within a single Locksmith.
- HSM integration; SPIFFE / workload identity.
- Detection of credential exfiltration *via* legitimate proxied traffic (cognitive-scanning territory, D-18).

### Q7: Technical risks and open questions

**Top risks for v2:**

1. **R-1 — SSE first-byte latency under TLS termination.** R-N6 caps added latency at 100ms first-byte. axum + reqwest streaming should comfortably meet this on warm connections, but TLS handshake on a cold pool entry, body decompression mismatches, or hyperscaler proxies between agent and Locksmith can introduce buffering. **De-risk:** M1 begins with the failing streaming integration test (PRD §kickoff "Suggested order of attack"); test asserts timing within 100ms of upstream first-byte chunk. Failures are diagnosed at the smallest scope.
2. **R-2 — M2 schema regret.** M2's schema (agents, bootstrap_tokens, audit) compounds into M3–M7. A wrong choice on `cert_identity` representation, `metadata` JSON shape, or audit `event_class` enumeration creates migration cost or compromises a future milestone. **De-risk:** PRD §kickoff requires schema sketch in this document *before* M2 code; this section is the sketch. Phase 5 will tighten the DDL; the schema review gate happens before the first M2 commit.
3. **R-3 — Constant-time token verification under structured-token lookup.** INF-5 says public-id lookup is timing-safe because the public id is non-secret. But: a B-tree lookup on `public_id` does still leak *whether the row exists*. An attacker who guesses many public ids could discover which are valid and which are not. **De-risk:** acceptable in v2 because the public id is 128 bits of randomness — guessing space is 2^128, infeasible by orders of magnitude. Document this in the threat model. If a customer raises it, add a "decoy lookup" pattern (always do an argon2-verify even on miss, against a stored-pepper hash).
4. **R-4 — Audit-write throughput vs proxy hot path.** Every proxied request writes a row. WAL mode (INF-21, Q-16) gives concurrent reads; the question is whether audit writes can keep pace at peak traffic. **Resolved per INF-26:** synchronous SQLite insert is the v2 default; M3 ships a benchmark task at 10/100/1000 sustained req/s; async-batched fallback is enabled only if measurements show >5ms 95th-percentile added latency or sustained queue depth >0. SQLite-as-audit envelope documented at ~1000 sustained writes/sec; beyond that, operators ship JSONL to a downstream audit store (composability per D-11). The escalation path is concrete; the default keeps audit canonical and simple.
5. **R-5 — mTLS deployment complexity (M6).** Operating an internal CA, distributing client certs to agents, refreshing CRLs — non-trivial for the homelab audience. **De-risk:** M6 ships a worked deployment example with `smallstep` / `step-ca`. `auth_mode: both` (D-8) supports incremental migration. mTLS is opt-in.
6. **R-6 — Streaming concurrency caps under bursty load.** Default 50/agent, 1000/process (Q-22). A legitimate burst that crosses 1000 returns 503 to legitimate agents. **De-risk:** caps are configurable; metrics expose utilization (INF-14); operators tune up if they hit the ceiling. M3+ adds metric `streaming_concurrency_high_water_mark` so operators see headroom.
7. **R-7 — Single-instance HA.** Locksmith is one process per host. A crash means no proxy, no admin. **De-risk:** systemd unit auto-restarts. State recovery on restart is fast (SQLite + ArcSwap config). Multi-instance HA is deferred per PRD §13; documented as a known limitation.

**Open questions cross-referenced from §2:**

All §2 questions Q-1..Q-27 are Resolved. Phase 4 will revisit each resolution against Phase 3's design surface for consistency; any tension surfaced there returns the affected question to Open status.

**Future risks (not v2 but worth recording):**

- **Cognitive-scanner-on-the-wire anti-pattern adoption.** A peer tool wraps LlamaFirewall behind an HTTP listener and asks Locksmith to route through it. D-18 forbids this composition; it would need to be re-litigated if a customer presses for it.
- **MCP-over-HTTP becomes dominant.** PRD §13 defers MCP bridging. If MCP becomes the agent ↔ tool wire format, Locksmith might need to *be* an MCP server, not bridge to HTTP services. Future milestone, post-v2.
- **Operator role granularity demand.** D-6 reserves the `scope` field on operator credentials. If a customer asks for fine-grained operator roles (read-only operator, agent-management-only operator), the schema is ready; the implementation is post-v2.

---

## 6. Implementation Plan

The PRD's seven milestones (M1..M7) are the implementation milestones. They were chosen for risk reduction (M1 hardens M0 streaming first; M2 builds the schema spine before any feature relies on it) and for incremental demonstrability (every milestone produces something an operator can test). This section translates each milestone into ordered tasks, testing requirements, documentation deliverables, and a risk-ordered delivery rationale.

### 6.0 Tracking system: GitHub Project + Issues

Tracked via GitHub rather than Linear for v2.

**Repository:** `SentientSwarm/agent-locksmith`
**Project:** `Agent Locksmith v2` (new GitHub Project, board view + roadmap view)
**Branch:** `develop` (current); merges to `main` at milestone completion
**Labels** (created on first M1 issue):
- `milestone:M1`..`milestone:M7` (one per PRD milestone)
- `component:listener`, `component:auth`, `component:repo`, `component:proxy`, `component:audit`, `component:secret`, `component:ratelimit`, `component:mtls`, `component:config`, `component:cli` (component:* matches §4.2 component types)
- `layer:listener`, `layer:auth`, `layer:service`, `layer:repository`, `layer:cross-cutting`, `layer:persistence` (layer:* matches §4.3)
- `kind:test`, `kind:doc`, `kind:bench`, `kind:infra`
- `risk:high`, `risk:medium`, `risk:low` (informs review priority and reviewer assignment)
- `R-FN`, `R-NN`, `UC-N`, `INF-N`, `D-N` — applied per issue to keep traceability live in GitHub search; `gh issue list --label R-F12` returns every issue covering that requirement
- `blocked` — applied when an issue cannot proceed; comment must name the blocker

**Issue title convention:** `M{N} (R-F{X}, R-N{Y}): T{N}.{M} — <task name>`. Example: `M1 (R-F12, R-N6): T1.1 — Failing SSE-passthrough integration test`.

**Issue body convention** (template lives at `.github/ISSUE_TEMPLATE/v2-task.yml`):
```
## Task
T{N}.{M} from docs/v2/SPEC.md §6.2.

## Component(s) and Layer
- Component: C-{N} (per §4.2)
- Layer: {layer name} (per §4.3)

## Covers
- UC-{...}, R-F{...}, R-N{...}, INF-{...}

## Acceptance criteria
- {bullet list, copied from §6.2}

## Test scenarios (if applicable)
- {bullet list of test names matching §5 Q5 / §6.2}

## Out of scope
- {anything that might look in-scope but isn't}
```

**Milestone ↔ Project column mapping:** the GitHub Project board uses one column per phase of work: `Backlog`, `Ready`, `In progress`, `In review`, `Done`. The v2 milestone (M1..M7) is a *label*, not a project column — issues across milestones can occupy the same column.

**Setup tasks** (one-time, before M1 work begins):
- Create the GitHub Project, configure board + roadmap views.
- Create labels listed above.
- Add `.github/ISSUE_TEMPLATE/v2-task.yml` matching the body convention.
- Create issues for every task listed in §6.2 (~70 issues). The PR template references the SPEC §4 component spec for cross-reference.

**Closing the loop:** every PR that closes an issue must update §4.1 traceability matrix coverage if it changes which UCs/requirements are satisfied, and must add a checklist line to the v0.{minor}.0 changelog entry under §7.

### 6.1 Milestone Overview

| # | Milestone | Scope summary | Dependencies | Exit criteria | T-shirt |
|---|-----------|--------------|--------------|---------------|---------|
| M1 | Inference-ready hardening | SSE/streaming passthrough; per-tool timeouts and body limits; `cloud:` → `egress:` rename via INF-24 deprecation registry; per-tool reqwest client pool (INF-25); SIGTERM + drain (INF-1); `/livez`, `/readyz`, `/version` (INF-3); structured tokens added (INF-5) preparing for M2 | None beyond M0 | Streaming integration test passes locally (`tests/streaming_passthrough_test.rs`); inference matrix integration tests against fixture + Ollama + LM Studio pass; long-running (>5min) generations complete; SSE first-byte ≤100ms over upstream first-byte; `cloud:` deprecation warns once with structured fields; `locksmith` shuts down within drain window | S–M |
| M2 | Agent identity, scoped authorization, admin substrate | SQLite + sqlx::migrate; full DDL (§4.6.2); `AgentRepository`, `BootstrapTokenRepository`, `AuditRepository` (writes deferred to M3, schema lives here); `AgentAuthenticator` trait + bearer impl; `OperatorAuthenticator`; `AdminService` + admin UDS; `RateLimiter`; `SecretBackend` trait + `EnvBackend`; typed `SecretRef` (INF-23); deprecation registry (INF-24); ConfigLoader hot reload + listener-shape carve-out (R-N5 amended); `locksmith` CLI for all M2 operations | M1 | All UC-1, UC-2, UC-3, UC-4, UC-5, UC-7 flows demonstrable via CLI; concurrent register/rotate tests pass (INF-9, INF-10); `locksmith bench auth` shows argon2 verify ~5ms (A-1 validation point); schema review gate signed off; `locksmith config reload` rejects listener-shape changes with structured error | L (load-bearing) |
| M3 | Governance audit log | `AuditRepository.record` + class-aware retention worker; optional `JsonlAuditSink` with bounded channel + drop-newest; `locksmith audit query` and `locksmith audit tail`; `locksmith export agents --format yaml`; audit indexes per §4.6.2; `audit_write_queue_depth` metric; benchmark task at 10/100/1000 req/s for INF-26 trigger evaluation | M2 | UC-8 query demonstrable; UC-10 export round-trips through git; audit JSONL drop-newest verified under slow-consumer test; retention prune verified on synthetic 1M-row table; M3 benchmark report attached as a comment to milestone closure issue | S–M |
| M4 | Admin HTTPS API | TLS-terminated admin HTTPS listener (C-3); same handler reuse from C-2; bearer auth (mTLS deferred to M6); off-by-default; bindable to a separate listener | M3 | UC-11 demonstrable; CLI and HTTPS produce identical results for equivalent operations; admin can be bind-restricted to localhost / Tailscale / public per config | S–M |
| M5 | Keys-at-rest hardening | `FileSealedBackend` (sealed-secret with systemd-creds or equivalent); systemd unit hardening directives; threat-model documentation; Vault and AWS Secrets Manager interfaces (impls deferred) | M4 (chronological) | Operator can deploy without any upstream credential in env vars or readable config; threat-model doc reviewed and merged; Vault/AWS interface documented but not implemented | M |
| M6 | mTLS support | `AgentAuthenticator` mTLS impl; `MtlsValidator` (CRL fetcher + local blocklist per Q-10); `auth_mode: bearer | mtls | both`; bootstrap-only listener (C-4) for mtls-only deployments; identity extraction from CN or configurable SAN; audit `auth_method` recorded | M2 (authenticator trait), M4 (admin API to harden), M5 (at-rest hardening) | UC-12 demonstrable; `bearer`, `mtls`, `both` modes all work; CRL refresh failure produces operator-visible metric; smallstep / step-ca worked example documented | M |
| M7 | Response-side controls | `ResponseControls` (max size, content-type allowlist, regex redaction); streaming preserved (size cap only) | M2 (per-agent context for redaction audit), M3 (audit redaction events) | Tools can be configured to reject responses >10MB, only `application/json`, and redact configured patterns; streaming flows unaffected | S |

T-shirt sizes are advisory and live in the separate `docs/v2/PLAN.md` artifact (per Q-1 resolution). They are *not* calendar commitments.

### 6.2 Milestone Details

#### M1 — Inference-ready hardening

**Goal:** Locksmith's existing M0 proxy correctly handles inference traffic alongside REST tool traffic. SSE/streaming passes through within 100ms of upstream first-byte; per-tool timeouts and body limits accommodate multi-minute generation; the `cloud:` → `egress:` rename ships with backward compat. The verification matrix passes against fixture, Ollama, LM Studio (cloud-provider tests local-only per Q-2).

**Dependencies:** None beyond M0.

**Exit criteria:**
- Integration test `streaming_passthrough_test.rs` passes (the M1 first failing test, per PRD §kickoff).
- Local-upstream inference matrix tests pass in default CI.
- Cloud-provider tests (Anthropic, OpenAI) pass when run locally with credentials.
- Long-running (>5min) generation completes under default config.
- `cloud:` field on a tool entry produces exactly one structured warning per process and is interpreted as `egress: proxied` / `egress: direct`.
- SIGTERM triggers drain; in-flight requests complete within 30s default; `locksmith` exits cleanly.
- `/livez`, `/readyz`, `/version` endpoints exist and behave per INF-3.

##### Tasks

| # | Task | Component | Layer | Size | Dependencies |
|---|------|-----------|-------|------|--------------|
| T1.1 | Failing integration test: SSE passthrough timing within 100ms of upstream first-byte (`tests/streaming_passthrough_test.rs`) | C-13 | service | S | — |
| T1.2 | Switch ProxyEngine response from `resp.bytes().await` to `Body::from_stream(resp.bytes_stream())`; T1.1 should now pass | C-13 | service | M | T1.1 |
| T1.3 | Per-tool reqwest client pool (`Arc<RwLock<HashMap<String, Arc<Client>>>>`); evict on hot reload of changed tool entries | C-13 | service / cross-cutting | M | T1.2 |
| T1.4 | Add per-tool `timeouts: { request_seconds, idle_seconds }` and `body_limit_bytes` config fields; replace M0 single `timeout_seconds` | C-18, C-13 | cross-cutting / service | S | T1.3 |
| T1.5 | Implement deprecation registry (DeprecationRegistry, DeprecationEntry); register `cloud → egress`, `telemetry: removed`, legacy `${VAR}` deprecation | C-18 | cross-cutting | M | — |
| T1.6 | Wire deprecation registry into config loader; verify one-shot warning per process; verify `cloud: true → egress: proxied` mapping; verify `telemetry:` accepted with warning | C-18 | cross-cutting | S | T1.5 |
| T1.7 | Add `egress: direct \| proxied` field with `#[serde(deny_unknown_fields)]` enabled; reject typo'd values | C-18 | cross-cutting | S | T1.5 |
| T1.8 | Local-upstream inference matrix integration tests: fixture (wiremock SSE), Ollama (skipped if `OLLAMA_HOST` unreachable), LM Studio (skipped if `LMSTUDIO_HOST` unreachable) | C-13 | service / kind:test | M | T1.4 |
| T1.9 | Cloud-provider integration tests: Anthropic, OpenAI (gated on env vars; local-only per Q-2) | C-13 | service / kind:test | S | T1.8 |
| T1.10 | ShutdownCoordinator: SIGTERM + SIGINT handlers; configurable drain window default 30s; listener-shutdown signaling | C-20 | listener | M | — |
| T1.11 | Split `/health` into `/livez`, `/readyz`, `/version` per INF-3; readyz reflects required-backend resolution | C-1 | listener | S | — |
| T1.12 | Structured tokens (`lk_<id>.<secret>`) — initial parser + generator only; not yet wired into auth path (M2 wires it) | (M2 prep) | auth | S | — |
| T1.13 | Documentation: M1 acceptance verification runbook (how to run streaming test locally, how to set up cloud creds, how to interpret deprecation warnings) | (kind:doc) | — | S | T1.9 |

##### Testing

| Test type | Scope | Key scenarios |
|-----------|-------|---------------|
| Unit | C-13 ProxyEngine | Per-tool client pool eviction on hot reload; egress-proxy URL plumbing; header stripping with new auth-header config |
| Unit | C-18 ConfigLoader | Deprecation registry: cloud rename mapping, telemetry removal, one-shot warning state machine; `deny_unknown_fields` rejecting typos; `egress` enum validation |
| Unit | C-20 ShutdownCoordinator | Drain window timing; signal handler installation |
| Integration | C-13 streaming | SSE chunks arrive within 100ms; long-running generation completes; body-limit enforcement; per-tool timeout enforcement |
| Integration | Local upstreams | Fixture + Ollama + LM Studio pass the same streaming-test shape |
| Integration | Cloud upstreams (local-only) | Anthropic, OpenAI streaming completes for representative prompt |
| Manual | Kamiwaza | Per PRD M1 — environment-dependent; not automated |

##### Documentation

| Artifact | Audience | Content |
|----------|----------|---------|
| `docs/v2/runbooks/m1-inference-hardening.md` | Operators | Setup steps for running the streaming test, interpreting deprecation warnings, switching from `cloud:` to `egress:`, enabling cloud-provider tests pre-PR |
| Inline rustdoc on `ProxyEngine`, `ShutdownCoordinator`, `DeprecationRegistry` | Developers | Public-API documentation per kickoff engineering standards |
| Updated `config.example.yaml` | Operators | Demonstrates `egress:` (current), references `cloud:` deprecation in comment |
| §7 changelog v0.2.0 entry | All | What changed; breaking-change notice for `cloud:` deprecation timeline |

---

#### M2 — Agent identity, scoped authorization, and admin substrate

**Goal:** Replace M0's single static token with per-agent identity. Introduce SQLite + sqlx; bring up the admin Unix socket; deliver the operator and agent-self-service CLI surfaces. Lay the audit table schema (writes happen in M3). This is the load-bearing milestone — schema decisions made here compound through M3..M7.

**Dependencies:** M1.

**Exit criteria:**
- All UC-1, UC-2, UC-3, UC-4, UC-5, UC-7 flows demonstrable via `locksmith` CLI against a running daemon.
- Concurrent rotate test (`concurrent_rotate_test.rs`) passes — exactly-one-success semantics (INF-9).
- Concurrent register-with-same-name test passes — bootstrap *not* consumed on conflict (INF-10).
- `locksmith bench auth` reports argon2 verify cost; argued against the A-1 assumption band (~5ms target, ≤10ms acceptable).
- Schema review gate: §4.6 DDL signed off by reviewer before any schema-touching code merges.
- `locksmith config reload` rejects listener-shape changes (port, auth_mode, TLS paths) with the structured error from §4.7.8.
- Admin Unix socket created with mode 0660, group `locksmith`; world-no-access verified by integration test (INF-7).
- Per-operator argon2-hashed credentials in operators.yaml work for all operator endpoints; missing operators file fails fast (R-N10).

##### Tasks

**Schema and persistence (foundational):**

| # | Task | Component | Layer | Size | Deps |
|---|------|-----------|-------|------|------|
| T2.1 | Add `sqlx` dep with `sqlite`, `runtime-tokio-rustls`, `migrate` features; remove unused alternatives if added | (infra) | persistence | S | — |
| T2.2 | Write `migrations/0001_init.sql` exactly per §4.6.2 (agents, bootstrap_tokens, audit, all indexes, CHECK constraints, PRAGMAs at connection-open) | C-19 | persistence | M | T2.1 |
| T2.3 | `MigrationRunner` module: open SqlitePool with INF-21 PRAGMAs; run migrations; verify schema version | C-19 | persistence | S | T2.2 |
| T2.4 | **SCHEMA REVIEW GATE.** Open issue `M2: schema review`; reviewer signs off before any further M2 schema-touching code merges | (kind:doc / kind:gate) | persistence | S | T2.2 |

**Repositories (after schema gate):**

| # | Task | Component | Layer | Size | Deps |
|---|------|-----------|-------|------|------|
| T2.5 | `AgentRepository`: create, get_active_by_public_id, get_by_name, get_by_cert_identity, list, update_policy, revoke, rotate (with WHERE-clause CAS), touch_last_used | C-8 | repository | L | T2.4 |
| T2.6 | `BootstrapTokenRepository`: mint, list, consume (atomic UPDATE WHERE used_at IS NULL pattern), revoke | C-9 | repository | M | T2.4 |
| T2.7 | `AuditRepository`: record (sync write), query, retention worker scaffold (no JSONL fan-out yet — that's M3) | C-10 | repository | M | T2.4 |

**Auth and tokens:**

| # | Task | Component | Layer | Size | Deps |
|---|------|-----------|-------|------|------|
| T2.8 | `argon2` dep + token-utility module: generate `lk_<id>.<secret>` tokens, hash secrets, verify (constant-time), zeroize on drop | (utility) | auth | M | T2.1 |
| T2.9 | `AgentAuthenticator` trait + `BearerAuthenticator` impl; constant-time secret verify, decoy-on-miss, audit on failure | C-6 | auth | M | T2.5, T2.8 |
| T2.10 | `OperatorAuthenticator`: load operators.yaml at startup, hot-reload on file change (NOT listener-shape — semantic config), per-operator argon2-verify | C-7 | auth | M | T2.8 |
| T2.11 | `RateLimiter`: per-IP token bucket + per-target failure counter; eviction; metric counter wiring | C-15 | cross-cutting | M | — |

**Admin protocol:**

| # | Task | Component | Layer | Size | Deps |
|---|------|-----------|-------|------|------|
| T2.12 | `AdminService` business-logic module: all methods per §4.2.14, no HTTP/YAML in this layer | C-12 | service | L | T2.5, T2.6, T2.7, T2.10 |
| T2.13 | Admin UDS listener: bind UDS, mode 0660, owner+group, stale-socket cleanup, dual-namespace router (`/admin/agent/*`, `/admin/operator/*`) | C-2 | listener | M | T2.9, T2.10, T2.11, T2.12 |
| T2.14 | Wire C-2 middleware: rate-limit, then auth (agent or operator depending on namespace); attach Identity to request extensions | C-2 | listener / auth | S | T2.13 |
| T2.15 | Agent-self-service handlers (register, status, rotate, deregister) — thin axum wrappers around AdminService | C-2 | service / listener | M | T2.13, T2.14 |
| T2.16 | Operator handlers (agents list/get/create/modify/revoke, bootstrap_tokens mint/list/revoke, tools list, audit-query stub deferred to M3) | C-2 | service / listener | M | T2.13, T2.14 |

**Configuration evolution:**

| # | Task | Component | Layer | Size | Deps |
|---|------|-----------|-------|------|------|
| T2.17 | Typed `SecretRef` enum + parsing (FromEnv, FromFileSealed, FromVault, FromAwsSecretsManager); legacy String shape with one-shot deprecation via INF-24 | C-14 | cross-cutting | M | T1.5 |
| T2.18 | Field-scoped `${VAR}` expansion (replaces M0 pre-parse expansion); INF-23 deprecation warning on legacy form | C-14 | cross-cutting | S | T2.17 |
| T2.19 | `SecretBackend` trait + `EnvBackend` impl; resolve at startup; degraded-mode per-tool override | C-14 | cross-cutting | M | T2.17 |
| T2.20 | ConfigLoader: atomic-validate-then-swap (INF-16); listener-shape diff detection + R-N5 carve-out rejection (Q-11); `deny_unknown_fields` (INF-17); deprecation registry already from M1 (T1.5) | C-18 | cross-cutting | M | T1.5, T1.6 |
| T2.21 | Startup-check sequencing (INF-2): DB reachable, migrations applied, secret backends resolved (or per-tool degraded), listeners bindable, admin socket creatable; fail-fast with structured error | C-19, C-2 | listener / cross-cutting | M | T2.3, T2.13, T2.19 |

**CLI:**

| # | Task | Component | Layer | Size | Deps |
|---|------|-----------|-------|------|------|
| T2.22 | `locksmith` CLI scaffold: clap, global flags, subcommand routing | (cli) | cli | S | — |
| T2.23 | `locksmith agent` subcommands (list, get, register, modify, revoke); UDS client; table+JSON+YAML formatters | (cli) | cli | M | T2.16, T2.22 |
| T2.24 | `locksmith bootstrap` subcommands (mint, list, revoke) | (cli) | cli | S | T2.16, T2.22 |
| T2.25 | `locksmith status`, `locksmith rotate` (agent self-service via env-var token) | (cli) | cli | S | T2.15, T2.22 |
| T2.26 | `locksmith tool list` (operator) | (cli) | cli | S | T2.16, T2.22 |
| T2.27 | `locksmith config reload`, `locksmith config show` | (cli) | cli | S | T2.20, T2.22 |
| T2.28 | `locksmith bench auth`: argon2 verify benchmark; emits result for A-1 assumption validation | (cli / kind:bench) | cli | S | T2.8 |
| T2.29 | `locksmith bench hash-operator-token`: takes a cleartext token on stdin, emits the argon2 hash for paste into operators.yaml | (cli) | cli | XS | T2.8 |

##### Testing

| Test type | Scope | Key scenarios |
|-----------|-------|---------------|
| Unit | Token utility | Roundtrip generate→hash→verify; bad input rejected; constant-time verify (statistically-tested) |
| Unit | AgentRepository | UNIQUE(name) enforcement; rotate WHERE-CAS semantics; revoke is idempotent; soft-delete excludes from active queries |
| Unit | BootstrapTokenRepository | consume is atomic and one-shot; expired/revoked rejected; concurrent consume → exactly-one-success |
| Unit | RateLimiter | Token-bucket refill; per-target lockout window; eviction of idle entries |
| Unit | ConfigLoader | Listener-shape diff detection; atomic swap on validation pass; previous config retained on failure; SecretRef parsing |
| Integration | `tests/admin_socket_test.rs` | UDS bind with mode 0660; world-other connect → EACCES; group-member connect → succeeds; operator-credential check on top |
| Integration | `tests/agent_lifecycle_test.rs` | UC-1 + UC-2 + UC-3 + UC-4 + UC-5 + UC-7 end-to-end; demonstrable via CLI |
| Integration | `tests/concurrent_rotate_test.rs` | Two simultaneous rotate calls → 1 success + 1 409 (INF-9) |
| Integration | `tests/concurrent_register_test.rs` | Two simultaneous register-same-name → 1 success + 1 409; bootstrap NOT consumed for failed call (INF-10) |
| Integration | `tests/listener_shape_reload_test.rs` | Reload with port change → rejected with structured error; reload with tool-only change → applied; deprecation warning emitted once |
| Integration | `tests/secret_backend_test.rs` | Env backend resolves; missing var with fail-fast → process refuses to start; missing var with degraded → tool surfaces as unavailable |
| Bench | `locksmith bench auth` | argon2 verify ≤10ms 95th percentile on commodity hardware (A-1 validation) |

##### Documentation

| Artifact | Audience | Content |
|----------|----------|---------|
| `docs/v2/runbooks/m2-onboarding.md` | Operators | Bootstrap mint → register → status → rotate workflow; operators.yaml format; admin UDS group setup |
| `docs/v2/schema-review-checklist.md` | Reviewers | Schema review gate criteria (T2.4) |
| Annotated `config.example.yaml` | Operators | Updated to current shape per §4.7.7 |
| Annotated `operators.example.yaml` | Operators | Per §4.7.7; instructions for `locksmith bench hash-operator-token` |
| Inline rustdoc on `AgentAuthenticator`, `OperatorAuthenticator`, `AdminService`, all repositories | Developers | Public-API doc |
| §7 changelog v0.3.0 entry | All | M2 features; breaking change: M0 `inbound_auth.token` removed in favor of per-agent tokens |

---

#### M3 — Governance audit log

**Goal:** Populate the audit table created in M2. Add the optional JSONL secondary sink. Deliver `locksmith audit query`, `locksmith audit tail`, `locksmith export agents`. Run the M3 benchmark task to validate INF-26 / Q-28 (synchronous-write strategy).

**Dependencies:** M2.

**Exit criteria:**
- Every proxied request (C-13) writes one audit row before returning to agent.
- Every admin operation writes an audit row before returning the response.
- UC-8 query demonstrable via `locksmith audit query --tool github --since 30d`.
- UC-10 export round-trips through git: `locksmith export agents > agents.yaml; git commit; rm db; locksmith import agents < agents.yaml` produces an equivalent state (modulo the cleartext-tokens-not-included contract per R-F14).
- JSONL drop-newest verified under a slow-consumer integration test.
- Class-aware retention prune verified on a synthetic 1M-row table.
- Benchmark report attached to the M3 closure issue: latency at 10/100/1000 sustained req/s; trigger evaluation of async-batched fallback per INF-26.

##### Tasks

| # | Task | Component | Layer | Size | Deps |
|---|------|-----------|-------|------|------|
| T3.1 | Wire `AuditRepository.record` into ProxyEngine forward path (success + failure paths) | C-10, C-13 | service | M | M2 |
| T3.2 | Wire audit writes into AdminService methods (every method writes one row, success or failure) | C-10, C-12 | service | M | M2 |
| T3.3 | Class-aware retention worker: hourly tokio interval; per-class DELETE WHERE ts < ?; row-count safety cap; metric counter on prune events | C-10 | repository | M | M2 |
| T3.4 | `JsonlAuditSink`: bounded mpsc channel (default 10000), drop-newest, daily+size rotation, schema_version=1, mirror-SQLite-columns format | C-11 | cross-cutting | M | M2 |
| T3.5 | Wire JsonlAuditSink as optional fan-out from AuditRepository.record (after SQLite commit succeeds); INF-22 startup-unreachable handling | C-11, C-10 | cross-cutting | S | T3.4 |
| T3.6 | `locksmith audit query` CLI subcommand: filters (since, until, agent, tool, event_class, decision, event); table+JSON+CSV formatters; cursor pagination | (cli) | cli | M | T3.1 |
| T3.7 | `locksmith audit tail` CLI subcommand: real-time follow via streaming admin endpoint | (cli) | cli / service | M | T3.1 |
| T3.8 | `locksmith export agents --format yaml`: serialize active agents (exclude cleartext tokens per R-F14); operator-only | (cli, AdminService) | cli / service | S | M2 |
| T3.9 | M3 benchmark task: `locksmith bench audit-write --rate {10,100,1000} --duration 60s`; emit p50/p95/p99 latency + audit_write_queue_depth high-water; report goes into milestone closure | (kind:bench) | cli | M | T3.1 |
| T3.10 | If T3.9 trips the INF-26 trigger (>5ms p95 added latency at any rate): implement bounded async-batched audit writer with `audit_write_queue_depth` gauge | C-10 | repository | L | T3.9 (conditional) |
| T3.11 | Audit-class assignment audit (review pass): every event source has the right `event_class`; every operator action gets `event_class=operator`; security events (auth_failure, bootstrap_reuse, rate_limited, agent_revoke) get `event_class=security` | (kind:doc / review) | service | S | T3.1, T3.2 |

##### Testing

| Test type | Scope | Key scenarios |
|-----------|-------|---------------|
| Unit | AuditRepository | record returns success on commit; query filters work; retention prune by class; row-count cap pruning order (proxy first) |
| Unit | JsonlAuditSink | Drop-newest under back-pressure; rotation at day boundary; rotation at size cap; startup-unreachable behavior |
| Integration | `tests/audit_query_test.rs` | UC-8 query against synthetic data; pagination; format JSON / CSV |
| Integration | `tests/audit_jsonl_backpressure_test.rs` | Slow consumer; drop counter increments; SQLite write succeeds; canonical record present |
| Integration | `tests/audit_retention_test.rs` | Synthetic 1M rows; retention prune within hourly cycle; row-count cap pruning |
| Integration | `tests/export_agents_test.rs` | UC-10: export → commit → wipe DB → import → state equivalent |
| Bench | `locksmith bench audit-write` | Run at 10/100/1000 req/s; report attached; INF-26 trigger evaluated |

##### Documentation

| Artifact | Audience | Content |
|----------|----------|---------|
| `docs/v2/runbooks/m3-audit.md` | Operators / compliance | Audit query patterns; JSONL sink configuration; retention tuning; example UC-8 queries |
| `docs/v2/audit-schema-v1.md` | Compliance / log-pipeline owners | JSONL schema reference; field semantics; schema_version policy (INF-12) |
| `docs/v2/runbooks/m3-export-import.md` | Operators | Backup workflow; UC-10; format spec; what's NOT in the export (cleartext tokens, R-F14) |
| Rustdoc on `AuditRepository`, `JsonlAuditSink` | Developers | Public-API |
| §7 changelog v0.4.0 entry | All | M3 features; INF-26 benchmark report summary |

---

#### M4 — Admin HTTP API

**Goal:** Expose the M2/M3 admin operations over HTTPS for remote management. Same handlers as the UDS; bindable to a separate listener; off-by-default; bearer auth (mTLS deferred to M6).

**Dependencies:** M3.

**Exit criteria:**
- UC-11 demonstrable: an operator with a token can run all CLI operations from a remote host via `--admin-url https://locksmith.example.com:9201`.
- CLI auto-detects local UDS first, falls back to admin HTTPS if `LOCKSMITH_ADMIN_URL` is set or `--admin-url` flag passed.
- Admin HTTPS listener can be bound to localhost-only, Tailscale IP only, or full network exposure based on config.
- Identical results between CLI-via-UDS and CLI-via-HTTPS for every admin operation.

##### Tasks

| # | Task | Component | Layer | Size | Deps |
|---|------|-----------|-------|------|------|
| T4.1 | Add server-side rustls deps: `rustls-pemfile`, `tokio-rustls` (or `axum-server` with rustls feature) | (infra) | listener | S | — |
| T4.2 | TLS cert/key loading from configured paths; cert/key validation at startup (fail-fast on missing/bad) | C-3 | listener | S | T4.1 |
| T4.3 | Admin HTTPS listener: same router shape as C-2; reuse C-12 AdminService and the C-2 handler functions | C-3 | listener | M | T4.2, M3 |
| T4.4 | CLI: detect admin URL via env var `LOCKSMITH_ADMIN_URL` or `--admin-url` flag; fall back to UDS if neither is set | (cli) | cli | S | T4.3 |
| T4.5 | Bootstrap-token registration over HTTPS: works regardless of `auth_mode` per D-10 | C-3 | listener | S | T4.3 |
| T4.6 | Listener-shape carve-out covers TLS cert/key paths: cert rotation requires restart; documented | C-18 | cross-cutting | XS | T4.2 |

##### Testing

| Test type | Scope | Key scenarios |
|-----------|-------|---------------|
| Unit | TLS cert loading | Missing file fails fast; bad PEM fails fast; valid loads |
| Integration | `tests/admin_https_test.rs` | End-to-end: TLS handshake, bearer auth, all major admin operations succeed; results match UDS path |
| Integration | `tests/admin_https_off_by_default_test.rs` | Default config does not bind HTTPS listener; explicit `enabled: true` required |

##### Documentation

| Artifact | Audience | Content |
|----------|----------|---------|
| `docs/v2/runbooks/m4-remote-management.md` | Operators | Setting up admin HTTPS; cert generation with smallstep; binding to Tailscale; CLI configuration via env var |
| Rustdoc on C-3 | Developers | Listener startup, cert handling |
| §7 changelog v0.5.0 entry | All | M4 features; remote management arrives |

---

#### M5 — Keys-at-rest hardening

**Goal:** Reduce the at-rest attack surface for upstream credentials. Add the file-sealed `SecretBackend`; ship systemd hardening directives; document the threat model. Vault and AWS interfaces ship as documented contracts only.

**Dependencies:** M4 (chronological).

**Exit criteria:**
- Operator can deploy with the file-sealed backend and have *no* upstream credential present in env vars or in any operator-readable config.
- systemd unit ships with hardening directives applied (`NoNewPrivileges`, `ProtectSystem=strict`, `PrivateTmp`, `ReadWritePaths` minimal, dedicated `locksmith` user).
- Threat-model doc reviewed and merged at `docs/v2/threat-model.md`.
- Vault and AWS Secrets Manager `SecretBackend` interface stubs exist with rustdoc on what an implementation must do; tests exist that verify the trait shape compiles.

##### Tasks

| # | Task | Component | Layer | Size | Deps |
|---|------|-----------|-------|------|------|
| T5.1 | `FileSealedBackend`: read sealed-secret file path from `SecretRef::FromFileSealed`; decrypt at startup using a key from `systemd-creds` or a configured path; cache resolved value (zeroized on drop) | C-14 | cross-cutting | L | M4 |
| T5.2 | systemd unit template: `locksmith.service` with hardening directives; ship at `dist/systemd/locksmith.service.template` | (kind:infra) | — | M | — |
| T5.3 | `VaultBackend` and `AwsSecretsManagerBackend` *trait stubs* (interface only): public type, function signatures, rustdoc; not registered in `SecretBackend` dispatch in v2 | C-14 | cross-cutting | S | M4 |
| T5.4 | Threat-model documentation: what at-rest hardening protects against; what it doesn't (running-process memory, kernel exploits, root compromise) | (kind:doc) | — | M | T5.1, T5.2 |
| T5.5 | Worked deployment example: openclaw-hardened Ansible role updated to use file-sealed backend; example config shipped in `dist/examples/sealed-secrets/` | (kind:doc / kind:infra) | — | M | T5.1 |

##### Testing

| Test type | Scope | Key scenarios |
|-----------|-------|---------------|
| Unit | FileSealedBackend | Decrypt happy path; missing file fails per `secret_backend_failure` policy; key-from-systemd-creds path |
| Integration | `tests/file_sealed_backend_test.rs` | Test fixture seals a value, Locksmith starts and resolves it, tool works |
| Integration | systemd hardening | Run Locksmith under the unit; verify it cannot write to `/etc`, cannot escalate, has private tmp |

##### Documentation

| Artifact | Audience | Content |
|----------|----------|---------|
| `docs/v2/threat-model.md` | All | What at-rest hardening protects against and what it doesn't (M5 explicit non-goals) |
| `docs/v2/runbooks/m5-sealed-secrets.md` | Operators | systemd-creds setup; sealing a secret; rotating a sealed secret |
| `dist/systemd/locksmith.service.template` | Operators | Drop-in unit with hardening directives |
| `dist/examples/sealed-secrets/` | Operators | Worked example |
| Rustdoc on SecretBackend impls | Developers | Implementation guide for future Vault/AWS impls |
| §7 changelog v0.6.0 entry | All | M5 features |

---

#### M6 — mTLS support

**Goal:** Cryptographic identity for agents and operators. `auth_mode: bearer | mtls | both`. CRL fetcher + local emergency blocklist. Bootstrap-only listener for mtls-only deployments.

**Dependencies:** M2 (authenticator trait), M4 (admin API to harden), M5 (at-rest hardening).

**Exit criteria:**
- UC-12 demonstrable: agent presents client cert, Locksmith validates against CA bundle + CRL + blocklist, maps cert identity to agent record, audits with `auth_method=mtls`.
- `bearer`, `mtls`, `both` modes all work end-to-end.
- CRL refresh failures produce operator-visible metric `mtls_crl_refresh_failures_total` and gauge `mtls_crl_age_seconds`; stale CRL still validates.
- Local blocklist `locksmith mtls revoke <serial>` immediately blocks the cert without waiting for CA refresh.
- Bootstrap-only listener (C-4) accepts only `register` regardless of `auth_mode`; operators can onboard new agents in mtls-only mode.
- Worked deployment example using smallstep documented.

##### Tasks

| # | Task | Component | Layer | Size | Deps |
|---|------|-----------|-------|------|------|
| T6.1 | Add deps: `x509-parser` for cert parsing; `rcgen` (dev-dep) for test cert minting | (infra) | auth | S | — |
| T6.2 | `MtlsValidator` core: parse cert; validate chain against CA bundle (rustls); check expiration; identity extraction (CN / SAN_DNS / SAN_URI) | C-16 | auth | M | T6.1 |
| T6.3 | CRL fetcher: periodic background task fetching from configured URL; parse PEM CRL; check serial-in-CRL on validation; metrics for refresh age and failures | C-16 | auth / cross-cutting | M | T6.2 |
| T6.4 | Local emergency blocklist: read `mtls.blocklist_path` file (one serial per line); hot reload on file change; check serial-in-blocklist on validation | C-16 | auth / cross-cutting | S | T6.2 |
| T6.5 | `MtlsAuthenticator` impl of AgentAuthenticator: extract peer cert from TLS state; call MtlsValidator; map identity to agent via `AgentRepository.get_by_cert_identity` | C-6 (mtls impl) | auth | M | T6.2, T2.5 |
| T6.6 | `auth_mode: bearer | mtls | both` configuration handling; `both` tries mTLS first, falls back to bearer if no client cert | C-18, C-1, C-3 | cross-cutting / listener | M | T6.5 |
| T6.7 | mTLS for the operator surface (D-9): admin HTTPS accepts operator client certs; map cert identity to OperatorRecord (operators.yaml gains optional `cert_identity` field) | C-7, C-3 | auth / listener | M | T6.5 |
| T6.8 | Bootstrap-only listener (C-4): server-TLS only, single endpoint `POST /admin/agent/register` | C-4 | listener | M | T6.6 |
| T6.9 | `locksmith mtls revoke <serial>`, `locksmith mtls list-blocklist`, `locksmith mtls crl-status` CLI commands | (cli) | cli | S | T6.4 |
| T6.10 | Audit `auth_method` field populated for every authenticated request (`bearer` / `mtls` / `bootstrap` / `operator`); INF-13 hashed-id form for security events | C-10 | service | S | T6.5 |
| T6.11 | Worked deployment example: smallstep + step-ca, agent cert provisioning via Ansible, openclaw-hardened role updated | (kind:doc / kind:infra) | — | L | T6.7, T6.8 |

##### Testing

| Test type | Scope | Key scenarios |
|-----------|-------|---------------|
| Unit | MtlsValidator | CN extraction; SAN DNS/URI extraction; CRL hit; blocklist hit; expired cert; untrusted CA; malformed cert |
| Unit | CRL fetcher | Successful refresh updates state; refresh failure preserves prior state; metrics increment |
| Integration | `tests/mtls_test.rs` | All three auth_modes; cert valid → success; cert in CRL → 401; cert in blocklist → 401; expired cert → 401 |
| Integration | `tests/mtls_both_mode_test.rs` | Mixed-fleet migration: agent A presents cert (succeeds via mtls), agent B presents bearer (succeeds via bearer); audit attributes correct method |
| Integration | `tests/bootstrap_only_listener_test.rs` | Listener accepts register; rejects all other endpoints |
| E2E | `tests/e2e_mtls_full_test.rs` | rcgen mints CA + agent cert; full auth flow; CRL refresh and revocation |

##### Documentation

| Artifact | Audience | Content |
|----------|----------|---------|
| `docs/v2/runbooks/m6-mtls-onboarding.md` | Operators | smallstep / step-ca setup; agent cert provisioning; operators with cert identity |
| `docs/v2/runbooks/m6-mtls-migration.md` | Operators | `bearer` → `both` → `mtls` migration sequence; per-agent visibility |
| `docs/v2/runbooks/m6-mtls-revocation.md` | Incident response | When to use CRL vs local blocklist; emergency revoke procedure |
| `dist/examples/smallstep/` | Operators | Worked example |
| Rustdoc on MtlsValidator, MtlsAuthenticator | Developers | Public-API |
| §7 changelog v0.7.0 entry | All | M6 features |

---

#### M7 — Response-side controls

**Goal:** Per-tool maximum response size, content-type allowlist, optional regex-based response redaction. Streaming flows preserved (only total-size cap applies to streaming).

**Dependencies:** M2 (per-agent context for redaction audit), M3 (audit redaction events).

**Exit criteria:**
- Operator can configure a tool to reject responses >10MB → request returns 502 with `response_size_exceeded`, audit event recorded.
- Operator can configure content-type allowlist `["application/json"]` → upstream returning `text/html` → 502 with `response_content_type_disallowed`.
- Operator can configure regex redaction patterns → matching strings replaced in non-streaming responses; redaction event recorded with hash of matched substring (NOT cleartext).
- Streaming flows (M1) unaffected: the SSE chunk path bypasses redaction; only total-size cap applies via a stream wrapper that emits a truncated indicator on cap-exceeded.

##### Tasks

| # | Task | Component | Layer | Size | Deps |
|---|------|-----------|-------|------|------|
| T7.1 | Per-tool config schema additions: `response: { max_size_bytes, content_type_allowlist, redaction_patterns }` per §4.7.7 | C-18 | cross-cutting | S | M3 |
| T7.2 | `ResponseControls.apply` for non-streaming: read body fully (subject to max_size_bytes), check content-type, apply redaction patterns, emit | C-17 | service | M | T7.1 |
| T7.3 | Streaming wrapper: a `Stream` adapter that counts bytes and emits a truncation marker on cap-exceeded; integrated into ProxyEngine streaming path | C-17, C-13 | service | M | T7.1 |
| T7.4 | Audit events for redaction (`event=response_redaction event_class=proxy details={"pattern_id": "...", "matches": N}`) and size cap (`event=response_size_exceeded`); cleartext NOT in details | C-10, C-17 | service | S | T7.2, T7.3 |

##### Testing

| Test type | Scope | Key scenarios |
|-----------|-------|---------------|
| Unit | ResponseControls | Size cap on non-streaming; content-type rejection; redaction with multiple patterns; regex compile errors fail config validation |
| Integration | `tests/response_controls_size_test.rs` | Non-streaming over cap → 502; streaming over cap → truncation marker; under cap → unaffected |
| Integration | `tests/response_controls_content_type_test.rs` | Rejected content-type returns 502 + audit event |
| Integration | `tests/response_controls_redaction_test.rs` | Configured pattern matches → redacted in response; audit records hash, not cleartext |
| Regression | M1 streaming tests | Re-run with response controls enabled on the test tool; first-byte latency still ≤100ms |

##### Documentation

| Artifact | Audience | Content |
|----------|----------|---------|
| `docs/v2/runbooks/m7-response-controls.md` | Operators | When to use each control; tradeoffs (redaction is regex, not DLP — composes with LlamaFirewall, D-18) |
| Rustdoc on ResponseControls | Developers | Public-API |
| §7 changelog v1.0.0 entry | All | v2 complete |

### 6.3 Risk-Ordered Delivery Sequence

The PRD's M1..M7 ordering is risk-driven. The rationale:

1. **M1 first because the M0 streaming gap is real and load-bearing.** R-N6's 100ms first-byte cap is unsatisfiable in M0 (`proxy.rs:95` buffers the full body). Every other milestone assumes streaming works. Starting with the failing streaming integration test (T1.1) per PRD §kickoff de-risks the M1 milestone before any code is written.

2. **M2 second because the schema is the spine.** Schema decisions in M2 (the §4.6.2 DDL) compound into M3..M7. M2 is the load-bearing milestone; it's also the largest. The schema review gate (T2.4) is the explicit pause point — no M2 schema-touching code merges until the schema is signed off. This matches the PRD §kickoff guidance ("get the schema right; migrations are expensive").

3. **M3 follows M2 because audit needs the agent identity model.** Audit rows reference `agent_public_id`; without M2's identity, audit is reduced to "what request happened" without "which agent did it." The synchronous-write strategy (INF-26) is the v2 default; the M3 benchmark (T3.9) is the empirical gate for the async-batched fallback (T3.10). Running the benchmark in M3 closes Q-28 with measurement, not theory.

4. **M4 follows M3 because the admin HTTPS surface needs the audit log to be valuable.** A remote-managed Locksmith without audit is an operations footgun.

5. **M5 follows M4 because at-rest hardening is most useful once the admin surface is in place.** M5 is also the smallest of the at-rest decisions: env-var backend (M2), file-sealed backend (M5), Vault/AWS interfaces (M5 interface-only). Operators with mTLS aspirations need at-rest hardening before mTLS to avoid the optical "strongest authentication fronting weakly-protected secrets" problem.

6. **M6 mTLS is late because it's high-complexity, low-frequency-of-use.** The hardened-agent-operator audience wants it; the homelab audience may never touch it. Building it last lets us learn from M2..M5's auth/admin surfaces and apply that to the M6 design. `auth_mode: both` (D-8) provides the migration runway.

7. **M7 is last because response-side controls compose with everything before.** Streaming preservation (M1) is a constraint on the M7 implementation; per-agent context (M2) is required for redaction audit; audit events (M3) are required to record redactions. Doing M7 last means it integrates against a stable substrate.

**Critical-path dependencies:**

- **M1 → M2:** the streaming change in M1 changes the `ProxyEngine` shape; M2 layers per-agent identity onto it. M2 cannot start audit-write integration without the M1 streaming path stable.
- **M2 → M3:** the schema gate T2.4 must close before M3 schema-touching work begins. Audit-table column shape is fixed in M2.
- **M2 → M6:** the `AgentAuthenticator` trait (T2.9) is the shape M6's mTLS impl plugs into. Without it, M6 would refactor the entire auth boundary.
- **M3 → M4:** admin HTTPS audit-write happens through M3's `AuditRepository`. M4 cannot ship without M3's audit fan-out.
- **M2 + M3 + M5 → M6:** see PRD M6 dependencies; M5 is chronologically required to argue M6's deployment-grade story.

**Parallel work opportunities (when team size allows):**

- M1 task T1.5 (deprecation registry) and T1.10 (ShutdownCoordinator) are independent — can run in parallel.
- Within M2: schema work (T2.1–T2.4) is foundational and serializes; thereafter, repository work (T2.5–T2.7), auth work (T2.8–T2.10), and CLI work (T2.22–T2.29) are independent and parallelizable until the AdminService (T2.12) integrates them.
- M4 admin HTTPS (T4.x) and M5 sealed-secret (T5.x) are independent and could overlap with one engineer per track.
- Within M6: T6.2/T6.3/T6.4 (validator core, CRL, blocklist) are independent components within the validator; T6.11 (worked smallstep example) overlaps freely with the implementation work.

**Where the plan is most fragile (top 3 integration risks):**

1. **The M1 streaming change (T1.2).** A single change point in `proxy.rs` flips response shape from buffered to streaming. Subtle bugs here (incorrect headers, premature stream-end, framing) are end-user-visible. Mitigation: T1.1's failing test is the contract; T1.8/T1.9 verify the change against real upstreams.
2. **The M2 schema compounding into M3..M7 (R-2 risk in §5 Q7).** Wrong column shape ripples. Mitigation: T2.4 schema review gate; §4.6.2 DDL is the artifact reviewed.
3. **The M3 sync-vs-async-batched audit-write decision (Q-28, INF-26).** If the M3 benchmark trips the trigger, T3.10 (async-batched fallback) is medium-complexity and pushes M3 timeline. Mitigation: T3.10 is conditional and only runs if T3.9 measures hot-path impact; the design (§4.2.12) keeps SQLite as canonical so the fallback is bounded in scope.

### 6.4 Definition of Done

A milestone is complete when *all* of the following hold:

- [ ] All tasks in §6.2 for the milestone are implemented and code-reviewed by at least one reviewer.
- [ ] All specified unit tests pass.
- [ ] All specified integration tests pass on commodity hardware in default CI; cloud-provider tests are run pre-PR per Q-2 policy.
- [ ] Bench tasks (where present) have results attached as a comment to the milestone closure issue.
- [ ] Documentation artifacts in §6.2 are written, reviewed, and merged.
- [ ] No P0 or P1 bugs remain on the milestone label.
- [ ] Systemic interfaces from §4.4 that the milestone touches are integrated (logging, metrics where applicable, audit, health endpoints).
- [ ] The §4.1 traceability matrix is updated if the milestone changes which UCs / requirements are covered.
- [ ] §7 changelog has a versioned entry summarizing the milestone.
- [ ] `cargo clippy -- -D warnings` and `cargo fmt --check` pass on the milestone branch (per PRD §kickoff engineering standards).
- [ ] The milestone branch is merged to `develop`; `main` receives the merge at the natural release cut (typically every 2 milestones, or at v1.0.0 = M7 closure).

**Release versioning:**

- v0.2.0 = M1 closure
- v0.3.0 = M2 closure
- v0.4.0 = M3 closure
- v0.5.0 = M4 closure
- v0.6.0 = M5 closure
- v0.7.0 = M6 closure
- v1.0.0 = M7 closure (v2 complete; first stable)

---

## 7. Changelog

### v0.1.0 — 2026-04-28
**Initial version** — Created via SoftwareDesign / CreateDesign workflow.

- Phase 1 (Requirements Augmentation): §1, §2 initialized, Appendix A workstreams per milestone, Appendix B cataloged UCs, R-Fs, R-Ns from PRD plus 22 inferred design requirements. All 12 PRD §14.1 resolved decisions inherited as Q-1..Q-12; 12 new design-phase questions Q-13..Q-24 raised and resolved within Phase 1.
- Phase 2 (Codebase Analysis): §3 fully populated against commit `f826694`. Module map, layer architecture, current API surface, M0 architectural decisions (M0-A1..M0-A5), platform interfaces, and M0→v2 responsibility migration matrix. Three new open questions Q-25..Q-27 surfaced and resolved within Phase 2: Q-25 (generalized deprecated-fields mechanism), Q-26 (typed `SecretRef` plus deprecated textual expansion — option C), Q-27 (reqwest client pool keyed on tool name). New INF-23 (typed `SecretRef`), INF-24 (generalized deprecated-fields tolerance, supersedes per-field shims), INF-25 (per-tool client pooling) added; INF-15 reframed to use the INF-24 mechanism.
- Phase 3 (Design Questions): §5 fully populated. Q1 enumerates 20 new components C-1..C-20; Q2 sketches the M2 SQLite schema (`agents`, `bootstrap_tokens`, `audit`), the consolidated v2 YAML config shape, and the new admin endpoints in both `/admin/agent/*` and `/admin/operator/*` namespaces; Q3 confirms single-binary single-instance scaling posture; Q4 enumerates external peers and what Locksmith expects from each; Q5 lays out unit/integration/E2E test strategy with one new integration test file per milestone gap; Q6 walks the defense-in-depth threat model; Q7 enumerates 7 top risks with de-risk strategies. Q-28 raised and resolved (synchronous audit writes default; benchmark-gated escalation to async-batched). New INF-26 documents the SQLite-as-audit scale envelope (~1000 sustained writes/sec) and the JSONL-to-downstream-store composability path beyond it.
- Phase 4 (Open Question Resolution): consistency-validation pass over §2. All 28 Q-rows confirmed Resolved with no contradictions across resolutions or against §3/§4/§5 design surface. Four deployment-time assumptions (argon2 verify cost, SQLite write throughput on commodity SSD, streaming-cap fd-limit assumption, "required backend" semantics for `/readyz`) surfaced and recorded in new §2.1 — they identify validation points for operators outside the assumed hardware/config band but do not reopen any design decision.
- Phase 5 (Design Proposal): §4 fully populated. §4.1 traceability matrix maps every UC and inferred requirement to one or more of components C-1..C-20. §4.2 component architecture: inventory, dependency diagram, and per-component specs (proportional depth: full Rust trait/struct shapes for security-critical components C-6, C-9, C-10, C-12, C-13, C-16, C-18; method-signature level for repositories C-8 and supporting modules; brief specs for listener-shape components C-1..C-5). §4.3 layer view extends the M0 architecture with new Authentication, Service, Repositories, Cross-cutting, and Persistence layers; per-layer design notes capture conventions and integration points. §4.4 systemic interfaces table covers logging, metrics (with full counter/gauge schema), config, auth, persistence, egress, and process supervision; failure modes documented for each. §4.5 six interaction sequences walk: bootstrap registration with reuse-attempt path, streaming proxy with capacity admission, operator-initiated revocation with downstream auth failure, hot reload with three rejection variants (unknown-field / listener-shape / valid), mTLS handshake with revocation, audit query. §4.6 consolidated data model: full DDL for `migrations/0001_init.sql` with constraints, partial indexes, and CHECK constraints on `event_class` / `decision`.
- Phase 6 (UX Mocks): §4.7 fully populated. Locksmith has no GUI; UX is the CLI surface, the YAML config-as-interface, and the structured HTTP error envelope. §4.7 documents: design conventions for CLI / YAML / errors; the `locksmith` command surface with sample invocations; three multi-step operator workflows (Ansible onboarding, agent rotation, compromise response); audit query output formats (table, JSON, tail); annotated YAML configuration as the deploy-time UX; configuration error message UX (unknown field, listener-shape change, deprecation warning); HTTP error envelope shapes operators see in `curl` (401 invalid_credential, 403 tool_not_allowed, 409 rotation_in_progress and agent_name_conflict, 429 rate_limited, 502 egress_proxy_failure, 503 streaming_capacity_exceeded and tool_credential_unavailable); state variations (empty, paginated, filtered, error); explicit non-goals (web UI, interactive TUI) deferred per PRD §13.
- Phase 7 (Implementation Plan): §6 fully populated. §6.0 commits to GitHub Project + Issues for tracking (not Linear) with label taxonomy (`milestone:M{N}`, `component:*`, `layer:*`, `kind:*`, `risk:*`, plus per-requirement labels for live traceability), issue title and body conventions, project board column mapping. §6.1 milestone overview table with M1..M7 scope, dependencies, exit criteria, and T-shirt sizes (advisory; calendar lives in `docs/v2/PLAN.md` per Q-1). §6.2 milestone details: per-milestone goal, exit criteria, ~70 ordered tasks across all milestones with component/layer/size/dependency columns, testing matrix, documentation deliverables. §6.3 risk-ordered delivery rationale: why M1 first (streaming gap is real and load-bearing), why M2 second (schema is the spine; review gate at T2.4), critical-path dependencies, parallel work opportunities, top 3 integration risks with mitigations. §6.4 Definition of Done with release-versioning map (v0.2.0 = M1 ... v1.0.0 = M7).

---

## Appendix A: Workstream Overviews

The PRD's seven milestones (M1–M7) are the workstreams. Each is a deliverable slice of the product with its own exit criteria. Dependencies and ordering are inherited from PRD §11.

### A1. M1 — Inference-ready hardening

**Priority:** P1 | **Wave:** 1 | **Estimate:** S–M (per `docs/v2/PLAN.md` once produced)

Make the existing M0 proxy correct for inference workloads. SSE/streaming passthrough, per-tool timeouts and body limits sufficient for multi-minute generation, the `cloud:` → `egress:` configuration rename, and a verification matrix covering Anthropic, OpenAI, Ollama, LM Studio, Kamiwaza, and a generic OpenAI-compatible local-proxy fixture.

**Source UCs:** UC-6, UC-13.
**Source requirements:** R-F12, R-F13, R-F18, R-N6.
**Bound by decisions:** D-11, D-15, D-17.
**Dependencies:** None beyond M0 (which has shipped).

### A2. M2 — Agent identity, scoped authorization, and admin substrate

**Priority:** P1 | **Wave:** 2 | **Estimate:** L (load-bearing milestone)

Replace the single-token model with per-agent identity, persistent state, and a first-class admin surface. SQLite schema for agents, bootstrap tokens, and audit (the audit table is created here but not populated until M3); pluggable `AgentAuthenticator` trait with bearer as v1 implementation; admin protocol over Unix domain socket with `/admin/agent/*` and `/admin/operator/*` namespaces; `locksmith` CLI for operator and agent self-service operations.

**Source UCs:** UC-1, UC-2, UC-3, UC-4, UC-5, UC-7, UC-10 (export sketched here, populated in M3).
**Source requirements:** R-F3, R-F4, R-F5, R-F6, R-F8, R-F9, R-F11, R-N1, R-N2, R-N3, R-N4, R-N5, R-N7, R-N8, R-N10.
**Bound by decisions:** D-2, D-3, D-4, D-5, D-6, D-7, D-12, D-13, D-14.
**Dependencies:** M1.

### A3. M3 — Governance audit log

**Priority:** P1 | **Wave:** 3 | **Estimate:** S–M

Populate the audit table created in M2. Audit writes happen for proxied requests, agent self-service operations, and operator operations. Optional secondary JSONL sink (mirror-SQLite-columns schema, bounded channel + drop-newest back-pressure). Configurable retention (90-day default, time-based) with row-count safety cap. CLI: `locksmith audit tail`, `locksmith audit query`, `locksmith export agents --format yaml`. Indexes on `(ts)` and `(agent_id, ts)` for query performance.

**Source UCs:** UC-8, UC-10.
**Source requirements:** R-F7, R-F14, R-N9.
**Dependencies:** M2.

### A4. M4 — Admin HTTP API

**Priority:** P1 | **Wave:** 4 | **Estimate:** S–M

Expose the M2/M3 admin operations over HTTPS for remote management. Same `/admin/agent/*` and `/admin/operator/*` namespaces. Bindable to a separate listener (port, address) from agent proxy traffic for blast-radius isolation. Off by default; explicit configuration to enable. TLS-required (no plaintext HTTP for admin). Bearer-token authentication for both agents and operators in v1; mTLS arrives with M6.

**Source UCs:** UC-11.
**Source requirements:** R-F10, R-N7.
**Dependencies:** M3.

### A5. M5 — Keys-at-rest hardening

**Priority:** P2 | **Wave:** 5 | **Estimate:** M

Pluggable `SecretBackend` trait with env-variable (default) and file-based sealed-secret backends. Stable interface for future Vault and AWS Secrets Manager backends (interface only, no implementations in M5). systemd unit hardening directives. Honest threat-model documentation about what at-rest hardening does and does not protect against.

**Source UCs:** none directly (cross-cutting infrastructural milestone).
**Source requirements:** R-F17, R-N2.
**Dependencies:** M4 (chronological, not strictly technical).

### A6. M6 — mTLS support

**Priority:** P2 | **Wave:** 6 | **Estimate:** M

`auth_mode: bearer | mtls | both` configuration. Certificate validation with configured CA bundle, expiration enforcement, and revocation support (CRL fetcher + Locksmith-local emergency blocklist per Q-10 / PRD §14.1 #10). Identity extraction from cert CN or configurable SAN field, mapping to an agent record. mTLS available for both agent traffic and operator traffic. Audit records the authentication method used. Worked deployment example with smallstep / step-ca / easy-rsa.

**Source UCs:** UC-12.
**Source requirements:** R-F16, R-N7.
**Bound by decisions:** D-7, D-8, D-9, D-10.
**Dependencies:** M2 (pluggable authenticator), M4 (admin API to harden), M5 (at-rest hardening).

### A7. M7 — Response-side controls

**Priority:** P2 | **Wave:** 7 | **Estimate:** S

Per-tool maximum response size (with default; configurable). Per-tool content-type allowlist. Per-tool optional regex-based response redaction. Streaming responses (M1 invariant) preserved — size/redaction apply to non-streaming responses; streaming subject only to total-size cap if configured.

**Source UCs:** none directly (defense-in-depth feature).
**Source requirements:** R-F15.
**Dependencies:** M2 (per-agent context for redaction audit), M3 (audit redaction events).

---

## Appendix B: Use Cases and Requirements

This appendix catalogs the PRD's requirement set verbatim, organized by workstream (milestone), and adds inferred requirements derived during design analysis. The PRD's identifiers (`UC-N`, `R-FN`, `R-NN`) are preserved unchanged; design-inferred items use the `INF-N` prefix.

### B.1 Use Cases (PRD §6)

The PRD already states each UC in narrative form. The Given/When/Then restatements below preserve the original identifier and capture the operational shape for traceability into design components and implementation tasks.

#### UC-1: Deploy-time agent registration via Ansible
**GIVEN** an Ansible playbook with a Locksmith operator credential
**WHEN** the playbook calls Locksmith's admin interface to register an agent with name, tool allowlist, and metadata
**THEN** Locksmith returns an agent token, persists the agent record, and the playbook writes the token into the agent's config so the agent calls Locksmith for tools without ever holding upstream credentials.

#### UC-2: Self-service rotation by an agent
**GIVEN** a long-running agent whose token is approaching expiration
**WHEN** the agent calls Locksmith's `rotate` endpoint with its current token
**THEN** Locksmith issues a new token, immediately invalidates the old token (D-13), and the agent continues operating without operator involvement.

#### UC-3: Self-service status retrieval
**GIVEN** an agent that has just booted
**WHEN** the agent calls Locksmith's `status` endpoint
**THEN** Locksmith returns the agent's identity, accessible tools, token expiration, and active state — and only that agent's data.

#### UC-4: Operator-initiated revocation
**GIVEN** an operator suspects an agent has been compromised
**WHEN** the operator runs `locksmith agent revoke <id>`
**THEN** the next request from that agent's token returns 401, the audit log records the revocation event and any subsequent denied requests, and the operator can later mint a new bootstrap token to onboard a replacement under a new identity (D-12).

#### UC-5: Bootstrap token for self-service onboarding
**GIVEN** an operator wants to onboard a new agent without writing the credential into config
**WHEN** the operator mints a single-use bootstrap token via the CLI and the deployment script presents it to Locksmith's `register` endpoint
**THEN** the agent receives its real credential and the bootstrap token is consumed (cannot be reused regardless of policy, R-F11).

#### UC-6: Inference traffic with credential separation
**GIVEN** an agent calling a chat-completion endpoint (Anthropic, OpenAI, Kamiwaza, Ollama, LM Studio, or any OpenAI-compatible upstream)
**WHEN** the agent sends a streaming request through Locksmith
**THEN** Locksmith injects the upstream credential, forwards the request byte-for-byte, passes SSE chunks through without buffering (R-N6), permits multi-minute generations under default config (R-F12), and the agent never sees the upstream API key.

#### UC-7: Tool discovery as a function of identity
**GIVEN** an agent and an operator both authenticated to Locksmith
**WHEN** each calls `GET /tools`
**THEN** the agent sees only tools that are (a) in its allowed set, (b) not in its denylist, and (c) configured with a valid credential; the operator sees all configured tools regardless of any agent's allowlist.

#### UC-8: Governance audit query
**GIVEN** a compliance reviewer asks "which agents called the GitHub API in the last 30 days, and what was the response status distribution?"
**WHEN** an operator runs `locksmith audit query --tool github --since 30d`
**THEN** Locksmith returns a structured answer with no credential values, suitable for compliance reporting.

#### UC-9: Composed deployment with Pipelock
**GIVEN** a deployment with both Locksmith and Pipelock in the egress path
**WHEN** an agent makes a credentialed call
**THEN** Locksmith authenticates the agent and injects the credential for every call, and Pipelock is in the path only for tools with `egress: proxied` (typically internet-bound). LAN-bound traffic transits Locksmith but not Pipelock (D-16).

#### UC-10: Backup, recovery, and inspection of agent state
**GIVEN** an operator wants to back up the agent fleet
**WHEN** the operator runs `locksmith export agents --format yaml`
**THEN** Locksmith emits agent state as YAML containing no cleartext tokens or credentials (R-F14), suitable for git, version control, or audit material.

#### UC-11: Remote management
**GIVEN** a platform engineer manages Locksmith on a remote host without SSH
**WHEN** the engineer calls Locksmith's HTTPS admin API with operator credentials
**THEN** the same operator operations available via CLI succeed, on a listener that is separate from agent proxy traffic (R-N7) and off-by-default for new deployments.

#### UC-12: mTLS-authenticated agents
**GIVEN** a deployment configured with `auth_mode: mtls` (or `both` during migration)
**WHEN** an agent presents a client certificate issued by a trusted CA
**THEN** Locksmith validates the certificate against the configured CA bundle, checks revocation (CRL + local blocklist per Q-10), maps the certificate identity (CN or configurable SAN) to an agent record, and audits the request with `auth_method: mtls`.

#### UC-13: Mixed-destination inference
**GIVEN** an operator runs LM Studio locally for some models and wants direct cloud-provider access for others
**WHEN** the operator configures two tool entries — `lmstudio` (`egress: direct`) and `anthropic` (`egress: proxied`)
**THEN** each tool entry has its own credential and its own egress treatment; the agent calls the appropriate tool depending on which model class it needs (D-15: one tool entry per destination policy).

### B.2 Functional Requirements (PRD §7)

R-F1 through R-F18 are reproduced verbatim from PRD §7 for traceability. The PRD is the authoritative source; this listing exists so that design-component traceability matrices in §4 of this document have local references to point to.

| ID | Statement (verbatim from PRD §7) |
|----|---------------------------------|
| R-F1 | Locksmith proxies HTTP requests from agents to configured upstream tools, injecting per-tool credentials, without the agent presenting any upstream credential. |
| R-F2 | Tools are configured statically in YAML (name, upstream URL, auth header and template, timeouts, `egress` flag selecting direct or proxied routing). |
| R-F3 | Each agent has a unique identity, an authentication credential (bearer token, later optionally mTLS), an optional tool allowlist, an optional tool denylist, optional metadata, optional expiration, and an explicit revocation state. |
| R-F4 | Locksmith exposes a self-service API for agents: `register` (with bootstrap token), `status`, `rotate`, `deregister`. An agent can only operate on its own record. |
| R-F5 | Locksmith exposes an operator API for cross-cutting management: list/get/modify/revoke any agent, mint and manage bootstrap tokens, query audit, list configured tools, view system status. |
| R-F6 | Tool discovery (`GET /tools`) returns only tools that are both (a) in the calling agent's allowed set and (b) configured with a valid credential. |
| R-F7 | Locksmith records every proxied request in a persistent audit log: timestamp, agent identity, tool, upstream host, method/path, response status, latency, policy decision. No credential values appear in the log. |
| R-F8 | Locksmith persists agents, tokens (hashed), bootstrap tokens, and audit records in a local SQLite database. Tools and infrastructure remain in YAML. |
| R-F9 | Operators have a CLI (`locksmith ...`) for all operator operations. The CLI talks to the running daemon over a Unix domain socket. |
| R-F10 | Locksmith optionally exposes the operator API over HTTPS for remote management, on a separate listener from agent traffic, off by default. |
| R-F11 | Bootstrap tokens may be single-use or reusable, scoped to a tool allowlist, and have an expiration. Consumed tokens cannot be reused regardless of policy. |
| R-F12 | Locksmith supports inference workloads: SSE/streaming responses pass through without buffering, configurable per-tool timeouts cover multi-minute generation, request and response size limits are configurable per tool. |
| R-F13 | Locksmith supports per-tool egress routing: `egress: proxied` routes the request through a configurable HTTP CONNECT proxy; `egress: direct` routes the request without proxy intermediation. The flag describes only the Locksmith→upstream hop. |
| R-F14 | Operators can export agent state to YAML for backup, version control, or inspection. Export contains no cleartext tokens or credentials. |
| R-F15 | Locksmith supports per-tool response controls: maximum response size, content-type allowlist, optional regex-based response redaction. |
| R-F16 | Locksmith supports mTLS as an alternative or additional agent authentication mechanism, configurable per-deployment via `auth_mode` (bearer, mtls, both). Certificate identity (CN or SAN) maps to an agent record. |
| R-F17 | Locksmith supports pluggable secret backends for upstream credentials: environment variables (default), file-based sealed secrets, with a stable interface for additional backends added without core changes. |
| R-F18 | Locksmith does not inspect or interpret request payloads to make routing or policy decisions. The `model` field in a chat completion request is data Locksmith forwards but does not interpret. |

### B.3 Non-Functional Requirements (PRD §8)

| ID | Statement (verbatim from PRD §8) |
|----|---------------------------------|
| R-N1 | Single binary distribution. No external runtime dependencies beyond a SQLite file. |
| R-N2 | Credentials are stored at rest only as either (a) environment variable references resolved at startup, (b) sealed-secret backend lookups, or (c) hashed (argon2) for agent and bootstrap tokens. Cleartext credentials never persist to disk in Locksmith's own storage. |
| R-N3 | Credentials are zeroized in memory on drop (`secrecy::SecretString` or equivalent). |
| R-N4 | No credential value ever appears in operational logs, audit logs, error responses, or API responses (cleartext credentials are returned exactly once, at registration or rotation, and never thereafter). |
| R-N5 | Configuration changes via YAML reload (ArcSwap) and database changes via admin operations both take effect without process restart, *except* for listener-shape changes (`auth_mode`, listener port, TLS certificate paths), which require a restart to rebind the listener under the new shape. |
| R-N6 | SSE/streaming proxying must not introduce buffering that delays first-byte more than 100ms beyond upstream first-byte. |
| R-N7 | Agent self-service endpoints enforce that the authenticated agent is the only valid subject; operator endpoints are reachable only with operator credentials and are bindable to a separate listener for blast radius isolation. |
| R-N8 | Locksmith is agent-platform-agnostic: any HTTP-speaking agent (OpenClaw, Hermes, Pi, custom) can use it without Locksmith-specific SDK code. |
| R-N9 | All audit and admin operations have an obvious, deterministic answer to "what was the policy decision and what data was the decision based on" — for compliance defensibility. |
| R-N10 | Operator credentials live in operator-only configuration (filesystem, not database), so the system is recoverable when the database is corrupted or missing. |

### B.4 Inferred Requirements [INFERRED]

Inferred requirements add design-phase clarifications that are implied by the PRD but not stated in implementable terms. Each traces to a source PRD requirement or use case, and each is justified by an operational, security, or correctness concern.

#### Operational and lifecycle

**INF-1: Graceful shutdown drains in-flight proxied requests** *(ref: R-F1, R-F12)*
GIVEN a SIGTERM is delivered to the Locksmith process
WHEN the process is handling in-flight proxied requests (including long-running streaming responses)
THEN the listener stops accepting new connections, in-flight requests are given a configurable drain window (default 30s) to complete, and after the window expires remaining connections are closed and the process exits.
**Rationale:** Without explicit drain behavior, deploys interrupt user requests. Streaming responses (R-F12, R-N6) make this especially visible.

**INF-2: Startup ordering and dependency checks** *(ref: R-N1, R-N5, R-F17)*
GIVEN Locksmith is starting
WHEN any of the following is required: SQLite file is reachable and migrations apply cleanly; secret backends configured for in-use tools resolve successfully; listener can bind to its configured port; admin Unix socket can be created with the configured permissions
THEN Locksmith starts only after all checks succeed; on any failure, Locksmith refuses to start with a structured error message naming the specific check that failed and exits with a non-zero status.
**Rationale:** Partial-start states (some tools work, others silently 502) are operationally worse than a clean refusal-to-start. R-N5's hot-reload assurance only applies once Locksmith is up.

**INF-3: Health and readiness endpoints follow k8s-style split** *(ref: R-F1, R-N7; resolves Q-18)*
GIVEN an operator or orchestrator queries `/livez`, `/readyz`, or `/version` on the agent listener
WHEN the process is up and serving
THEN `/livez` returns 200 unless the process is unrecoverably broken; `/readyz` returns 200 only when the database is reachable, the agent listener is bound, and all *required* secret backends have resolved (per INF-4 / Q-17 — degraded-mode tools do not fail readiness); `/version` returns the build commit SHA, build date, and crate version. All three are unauthenticated and on the agent listener; on `/readyz` failure, the response body names the failing check.
**Rationale:** k8s-shaped liveness/readiness is the lingua franca for orchestrators and degrades gracefully under degraded-mode operation. `/version` is uncontroversial and useful for incident response.

**INF-4: Secret-backend startup behavior is configurable** *(ref: R-F17, R-N2; resolves Q-17)*
GIVEN one or more configured `SecretBackend` lookups fail at startup (env var unset, sealed-secret file unreadable)
WHEN the process starts
THEN behavior is determined by a two-level configuration: a global `secret_backend_failure: fail-fast` (default) | `degraded` setting and a per-tool override `on_secret_failure: degraded` that opts an individual tool out of the global default. Tools that fail to resolve under `degraded` mode are surfaced as unavailable in `GET /tools` and return 503 on direct calls; their state is exposed as a metric.
**Rationale:** Mixed-criticality deployments (a must-work production tool plus a would-be-nice dev tool on the same Locksmith) need per-tool granularity; the safe global default remains fail-fast.

#### Security guards

**INF-5: Structured tokens with public id and constant-time secret verification** *(ref: R-N4; resolves Q-13, Q-14)*
GIVEN any token issued by Locksmith (agent token, bootstrap token, operator token)
WHEN the token is shaped, stored, and verified
THEN the wire format is `lk_<public-id>.<secret>` where `<public-id>` is a 128-bit URL-safe identifier (non-secret) and `<secret>` is a 256-bit URL-safe random value; the database stores `(public_id, secret_hash)` keyed by `public_id`; verification looks up the row by `public_id` (timing-safe because `public_id` is not secret), then verifies the presented `<secret>` against `secret_hash` using argon2id with parameters `m=4 MiB, t=3, p=1` (configurable per deployment); `secret_hash` and any in-memory copies of the cleartext secret are zeroized on drop (R-N3).
**Rationale:** Industry-standard pattern (Stripe, GitHub) for exactly this problem — keeps lookup fast and timing-leak-free while making the secret-comparison step constant-time. argon2id parameters are tuned for token verification frequency (~5ms/verify) rather than human-password verification frequency, since 256-bit random tokens have 1.16e77 entropy and don't need OWASP-login-grade cost.

**INF-6: Rate limiting on register, rotate, and operator endpoints** *(ref: R-N7, R-F4, R-F5; resolves Q-15)*
GIVEN repeated calls to `register`, `rotate`, or operator-API endpoints
WHEN the call rate exceeds a configured threshold
THEN: (a) `register` is rate-limited per source IP with a default token bucket of 60 req/min; (b) `rotate` and operator endpoints are rate-limited both per source IP (60 req/min) and per target-token-public-id on *failed verification only* (10 failures / 5 min lockout). On overflow, requests return `429 Too Many Requests` with a `Retry-After` header, an audit event of `event: rate_limited` is written, and the `rate_limited_total` metric counter increments. State is kept in-memory (single-instance Locksmith); revisit if multi-instance HA emerges.
**Rationale:** Bounds brute-force attempts on leaked bootstrap or rotation tokens. Per-IP plus per-target on `rotate` ensures one legitimate agent retrying does not lock out another agent at the same IP, while still bounding attack rate.

**INF-7: Admin Unix socket access is two-layered** *(ref: R-F9, R-N7; resolves Q-24)*
GIVEN Locksmith creates the admin Unix domain socket at startup
WHEN the socket is created and a caller connects
THEN: (a) the socket is created with mode 0660 (owner+group read/write, world-none), owner `locksmith` user, group `locksmith` (configurable). (b) Connection alone is not sufficient; the caller must additionally present a valid operator credential (per Q-4 / PRD §14.1 #4) that is verified by the admin handler. Failure at the filesystem layer returns `permission denied` at connect; failure at the credential layer returns `401 invalid_credential` and is audited.
**Rationale:** Two layers — filesystem permission gates *who can talk to the socket* and operator credential gates *what they can do*. A misconfigured socket permission becomes a fail-closed condition (operators denied at connect) rather than silent privilege escalation; a valid socket connection from an unauthenticated caller still cannot perform any operator action.

**INF-8: TLS server-cert refresh without restart is constrained** *(ref: R-N5, R-F10)*
GIVEN the TLS certificate file used by the admin HTTPS listener is rotated on disk
WHEN the file is replaced
THEN Locksmith does not pick up the new cert without a restart (consistent with R-N5's listener-shape exception); operators are expected to restart on cert rotation, and this is documented.
**Rationale:** Hot cert reload is technically possible but adds substantial complexity. v1 ships restart-required, matching the broader listener-shape policy.

#### Correctness and concurrency

**INF-9: Concurrent rotate by the same agent yields a deterministic outcome** *(ref: UC-2, R-F4; resolves Q-20)*
GIVEN two concurrent `rotate` calls authenticated as the same agent
WHEN the calls reach the daemon simultaneously
THEN exactly one succeeds and returns a new token; the other returns `409 Conflict` with `{"error": "rotation_in_progress"}`. The succeeded rotation is the one whose database transaction commits first; the loser's old credential remains valid until the winner's commit invalidates it (D-13 immediate invalidation).
**Rationale:** First-committer-wins gives a clean audit trail (one rotation event, one rotator identity) and lets client libraries handle the 409 with a simple retry-with-new-credential. The alternative (idempotent last-writer-wins) was rejected for producing a confusing audit story when two concurrent rotators each get the same new token.

**INF-10: Concurrent register with the same agent name fails the second** *(ref: UC-1, UC-5, R-F3)*
GIVEN two simultaneous `register` calls attempting to create agents with the same name
WHEN the calls reach the daemon simultaneously
THEN exactly one succeeds (UNIQUE constraint on `agents.name`); the other returns 409 with `{"error": "agent_name_conflict"}` and the bootstrap token (if used) is *not* consumed for the failing call.
**Rationale:** Token consumption on a failed register attempt would force the operator to mint a new bootstrap token to retry — bad UX. Token consumption is conditional on register success.

**INF-11: SQLite migrations are forward-only and version-tracked** *(ref: R-F8, R-N1)*
GIVEN a SQLite database created by an earlier Locksmith version
WHEN a newer Locksmith version starts
THEN any pending migrations apply automatically, version metadata is updated atomically, and a downgrade is not supported (operators use database backup + restore for rollback).
**Rationale:** Forward-only is `sqlx::migrate!`'s natural operating mode (Q-5 resolution). Documenting the no-downgrade contract avoids customer expectations of two-way migration.

#### Audit and observability

**INF-12: Every audit event carries a stable schema version** *(ref: R-F7, R-N9)*
GIVEN any audit record written to the SQLite audit table or the JSONL secondary sink
WHEN the record is written
THEN the record includes a `schema_version: <integer>` field whose value is incremented when the audit schema changes in a non-additive way.
**Rationale:** Compliance reviewers and log-shipping pipelines need an unambiguous way to know what fields to expect. Additive changes (new optional columns) do not bump the version; removals or renames do.

**INF-13: Failed authentication is audited as a security event with hashed identifier** *(ref: R-F7, R-N4, UC-4)*
GIVEN any authentication failure (invalid bearer, expired token, revoked token, mTLS handshake failure, bootstrap reuse attempt)
WHEN the failure occurs
THEN an audit record of `event: auth_failure` is written with: timestamp, origin (IP for HTTPS listeners, peer cred for admin socket), reason code, hashed token identifier (for bearer; certificate fingerprint for mTLS), and *no* token cleartext.
**Rationale:** Compliance defensibility (R-N9) requires authentication failures be traceable. Cleartext suppression (R-N4) requires the identifier be hashed.

**INF-14: Process metrics surface is opt-in, Prometheus-pull-shaped** *(ref: R-N1, R-N9; resolves Q-19)*
GIVEN a Locksmith deployment configured with metrics enabled
WHEN an operator configures `metrics: { enabled: true, port: 9091 }`
THEN Locksmith exposes a Prometheus text-format `/metrics` endpoint on the configured port, separate from agent and admin listeners. Counters cover proxied-request totals (labeled by tool and response status class), authentication events (labeled by outcome and method), rate-limited events, audit-sink dropped records, streaming-concurrency utilization, secret-backend degraded-tool count, and process resource use. OTel push export is not implemented in v2.
**Rationale:** Prometheus-pull is the de-facto standard for self-hosted services and aligns with R-N1's single-binary spirit (no outbound dependency at runtime). OTel adds infrastructure that most homelab operators do not run; defer until customer pull justifies it.

#### Configuration and operability

**INF-15: `cloud:` deprecation handled via generalized deprecated-fields mechanism** *(ref: R-F13, M1; supersedes ad-hoc per-field shim)*
GIVEN a configuration file using the legacy `cloud: true` field on a tool entry
WHEN Locksmith loads the configuration
THEN the field is interpreted (`cloud: true` → `egress: proxied`, `cloud: false` → `egress: direct`) and a one-shot deprecation warning is emitted via the mechanism described in INF-24. Subsequent reloads do not re-emit the warning unless the deprecation registry is reset.
**Rationale:** PRD M1 requires backward-compatibility shim with deprecation warning. Coalescing this with the broader removed-fields mechanism (INF-24) avoids one-off shim code per deprecated field.

**INF-16: YAML config reload is atomic and validated** *(ref: R-N5, R-F2)*
GIVEN an operator updates the YAML configuration file
WHEN the file changes (file-watch trigger or SIGHUP)
THEN Locksmith parses and validates the new configuration in full *before* swapping; on any validation error, the previous configuration remains active and a structured error is logged identifying the offending field.
**Rationale:** A partial swap that leaves Locksmith in an inconsistent state is worse than refusing the reload. ArcSwap (R-N5 mention) gives the atomic-swap primitive; validation discipline gives the safety.

**INF-17: Configuration parsing rejects unknown fields with structured error** *(ref: R-F2, R-N5)*
GIVEN a YAML configuration file containing fields Locksmith does not recognize
WHEN Locksmith parses the file at startup or hot reload
THEN parsing fails (or for hot reload: the reload is rejected and previous config retained) with a structured error naming the unknown field and the path within the document where it was encountered.
**Rationale:** Silent ignoring of typo'd fields produces deployments where the operator believes a setting is in effect when it is not. Strict parsing surfaces these errors at the moment of misconfiguration.

#### Capacity and limits

**INF-18: Streaming-response concurrency is bounded with two layers** *(ref: R-F12, R-N6; resolves Q-22)*
GIVEN per-agent and process-wide caps on concurrent streaming responses
WHEN a new streaming request arrives
THEN the request is admitted only if both the per-agent counter (default cap 50) and the global counter (default cap 1000) are below their thresholds; if either is at threshold, the request returns `503 Service Unavailable` with a structured body identifying which limit was hit and a `Retry-After` hint, an audit event of `event: streaming_capacity_exceeded` is written, and the matching metric counter increments. Both caps are configurable; both surface as gauges via the metrics endpoint (INF-14).
**Rationale:** Streaming responses tie up file descriptors and memory; a single hostile or buggy agent should not be able to exhaust the process budget. Per-agent fairness plus a global ceiling protects both other agents and the OS-level FD/connection limits.

**INF-19: Audit retention is class-aware with a row-count safety cap** *(ref: R-F7, R-N9; resolves Q-23)*
GIVEN audit records carry an `event_class` column with values `proxy`, `operator`, or `security`
WHEN the audit retention worker runs (periodic, default hourly)
THEN records are pruned according to per-class retention windows: `audit.proxy_retention_days` (default 90), `audit.operator_retention_days` (default 365), with security-class events folded into the operator-retention window; in addition, a configurable global row-count cap (default 10M rows) prunes the oldest `proxy`-class records first when exceeded, with a metric counter recording the over-cap pruning event.
**Rationale:** Compliance reviewers care about operator actions over much longer windows than proxied-call volume; one global retention forces either short operator history or unreasonable proxy-event disk cost. Two windows match how compliance teams actually reason about audit. Row-count cap is the safety net for traffic spikes that could exhaust disk inside the 90-day window.

#### Composition with peers

**INF-20: HTTP CONNECT proxy failures for `egress: proxied` tools are surfaced cleanly** *(ref: R-F13, UC-9)*
GIVEN a tool configured with `egress: proxied` and a configured HTTP CONNECT proxy (typically Pipelock)
WHEN the configured proxy is unreachable, refuses the connection, or returns a non-2xx CONNECT response
THEN Locksmith returns 502 Bad Gateway to the agent with a structured body identifying the proxy as the source of the failure (without leaking proxy credentials), and an audit event records `egress_proxy_failure`.
**Rationale:** When Pipelock is down, agents currently see opaque connection errors. A structured signal lets agent code distinguish "upstream is down" from "proxy is down."

#### Persistence and backpressure

**INF-21: SQLite is opened in WAL mode with tuned PRAGMAs** *(ref: R-F8, R-N1; resolves Q-16)*
GIVEN the SQLite database file backing agents, bootstrap tokens, and audit
WHEN Locksmith opens the database at startup (and on every connection acquired from the pool)
THEN the following PRAGMAs are applied: `journal_mode=WAL`, `synchronous=NORMAL`, `wal_autocheckpoint=1000`, `foreign_keys=ON`, `busy_timeout=5000`. The presence of `<dbfile>-wal` and `<dbfile>-shm` sidecar files is documented as expected. The `locksmith maintenance checkpoint` CLI exposes `wal_checkpoint(TRUNCATE)` for operator-driven WAL compaction.
**Rationale:** WAL mode allows agent auth reads not to block on audit writes — essential for the proxy's mixed read+write workload. `synchronous=NORMAL` gives substantially higher write throughput than `FULL`; the durability tradeoff (last second of audit could be lost on power loss) is small and the optional JSONL secondary sink (per PRD §14.1 #6) covers that gap when configured.

**INF-22: JSONL audit sink unreachable at startup is non-fatal by default** *(ref: R-F7, PRD §14.1 #6; resolves Q-21)*
GIVEN a configured JSONL audit sink path is unreachable at startup (mount missing, parent directory permissions wrong, disk full)
WHEN Locksmith starts
THEN by default the JSONL sink is marked disabled, a warning is logged, the `audit_jsonl_disabled` metric is set to 1, and Locksmith continues to start with SQLite as the system of record. Operators that require the JSONL sink for compliance pipelines opt into fail-fast behavior via `audit.jsonl_required: true`, which causes startup to refuse with a structured error naming the JSONL path.
**Rationale:** PRD §14.1 #6 already declares SQLite the system of record and JSONL "best-effort ship-out"; refusing to start when only the best-effort path is broken would violate that layering. The `audit.jsonl_required` opt-in covers compliance deployments where any record loss is unacceptable.

#### Configuration evolution and credential references

**INF-23: Typed `SecretRef` fields and deprecated textual `${VAR}` expansion** *(ref: R-F2, R-F17, M0-A4; resolves Q-26 with option C)*
GIVEN any field in the YAML config that carries a credential or secret value (currently `inbound_auth.token` and `tools[].auth.value`; later, anywhere `R-F17`'s `SecretBackend` resolution applies)
WHEN the field is parsed
THEN it accepts two shapes: (a) a string containing one or more `${VAR_NAME}` patterns, processed by the legacy textual expander but only after the value has passed YAML parsing as a string (i.e., expansion is field-scoped, not pre-parse); (b) a typed `SecretRef` mapping that names the backend explicitly, e.g.:
```yaml
value: { from_env: "GITHUB_TOKEN", prefix: "Bearer " }
value: { from_file_sealed: "/etc/locksmith/secrets/github.token.sealed" }
value: { from_vault: "secret/locksmith/github" }   # post-M5 backends
```
The legacy string-with-`${VAR}` form emits a single deprecation warning per Locksmith process via the INF-24 mechanism, citing the field path and recommending the typed form. The textual pre-parse expansion in `src/config.rs::expand_env_vars` is removed; M0 deployments that rely on it migrate to either field-scoped string expansion (no schema change required) or the typed form. Pre-parse expansion is removed because of the YAML-significance fragility (M0-A4): values containing `:`, leading whitespace, or `null` produced silently incorrect parses.
**Rationale:** A typed `SecretRef` is the schema shape M5's `SecretBackend` trait wants to drop into without a second migration. Pre-parse textual expansion was a v0 expedient; it is fragile and silently corrupts. Field-scoped string expansion preserves the simple operator experience for the dominant case (`value: "Bearer ${TOKEN}"`) while eliminating the YAML-escape hazard. The typed form is documented as the recommended shape for new deployments and the only shape supported under future `SecretBackend` implementations beyond env-var.

**INF-24: Generalized deprecated/removed-fields tolerance with one-shot warnings** *(ref: R-F2, R-N5; resolves Q-25; supersedes per-field deprecation shims)*
GIVEN the configuration parser maintains a registry of deprecated and removed fields with metadata (`name`, `replacement`, `disposition: deprecated | removed | renamed`, `since_version`, `removal_target_version`)
WHEN parsing encounters a registered field
THEN the field is processed according to its disposition (`renamed`: aliased to the new name; `deprecated`: accepted with a warning; `removed`: ignored with a warning), exactly one warning is emitted per field per Locksmith process (rate-limited via a `Once`-style registry, reset on hot reload to allow operators to verify resolution after a config change), and the warning is structured (field name, recommended action, version metadata).
The initial registry covers: `cloud:` (renamed → `egress:` per INF-15 / M1), `telemetry:` (removed; OTel deferred per Q-19; previously dead-code in M0), and the legacy string-with-`${VAR}` form on secret-bearing fields (deprecated → typed `SecretRef`, per INF-23).
**Rationale:** Per-field shim code accumulates as the config schema evolves. A single mechanism covers `cloud:` (M1), the `TelemetryConfig` dead-code cleanup (Q-25), and the textual-expansion deprecation (INF-23). Future schema changes — adding fields, renaming fields, removing fields — register a single entry rather than adding a one-off branch in the loader.

**INF-25: Per-tool reqwest client pooling keyed on tool name** *(ref: R-F1, R-F12, R-F13, M0-A3; resolves Q-27)*
GIVEN the proxy handler currently builds a fresh `reqwest::Client` per request, defeating connection pooling
WHEN the configuration is loaded (or hot-reloaded)
THEN Locksmith maintains a `HashMap<String, Arc<reqwest::Client>>` (or equivalent concurrent map) keyed on tool name; each entry is constructed lazily on first use of that tool and carries the tool's timeout, egress configuration (HTTP CONNECT proxy when `egress: proxied`), and TLS settings; on YAML hot-reload (R-N5), entries for tools whose configuration changed are evicted and recreated on next use; entries for unchanged tools are retained.
**Rationale:** PRD §D-15 commits to "one tool entry per destination policy" — a tool is the unit of egress treatment, credential, and timeout, so pooling per tool matches the conceptual model. Lazy construction keeps startup fast; eviction on hot-reload keeps the pool in sync with config.

#### Scale envelope and audit-write strategy

**INF-26: Audit-write strategy is synchronous by default with a documented scale envelope** *(ref: R-F7, R-F8, R-N1, INF-19, INF-21; resolves Q-28)*
GIVEN the audit table is the canonical record of every credentialed call (R-F7) and SQLite is the persistence substrate (R-F8, R-N1)
WHEN the proxy handler completes a request
THEN by default a single-row `INSERT` is performed synchronously on the request-completion path before returning to the agent. The audit row is canonical the moment the agent sees the response; there is no loss window on crash. The proxy handler exposes `audit_write_queue_depth` as a metric (which under synchronous mode is always 0); M3 ships a benchmark task that measures synchronous audit-write latency at 10, 100, and 1000 sustained req/s on commodity SSD. Async-batched mode (bounded mpsc channel, batched `INSERT`s every 100 rows or 100ms, SQLite still canonical) is the fallback enabled only if the benchmark shows >5ms (95th percentile) added proxy-hot-path latency *or* an operator observes sustained `audit_write_queue_depth > 0` after enabling async mode for diagnosis.

**Documented scale envelope:**
- SQLite as audit system-of-record is sized for **up to ~1000 sustained writes per second** on commodity hardware. The PRD's stated audiences (hardened single-agent, homelab, Kamiwaza-typical multi-agent) sit at 1–100 sustained writes/sec.
- Beyond ~1000 sustained writes/sec, the recommended pattern is to enable the JSONL secondary sink (PRD §14.1 #6) and ship to a downstream audit store (Loki, Splunk, ClickHouse, Vector pipeline). SQLite remains the recent-history queryable cache; the downstream store handles long-term retention and cross-instance fleet queries. This pattern aligns with D-11 / D-16: a scaled audit store is its own product; Locksmith composes with it via JSONL.
- Class-aware retention (INF-19) and row-count safety cap keep the SQLite table operationally healthy even at the upper end of the envelope.

**Operator-facing documentation note (M3):** the deployment guide states the scale envelope explicitly so operators sizing for >1000 writes/sec configure the JSONL sink from day one rather than discovering the limit operationally.

**Rationale:** Locksmith's R-N1 single-binary-plus-SQLite constraint is load-bearing for the homelab audience and operationally clean for everyone in the targeted scale band. SQLite WAL-mode write capacity (5–20k single-row INSERTs/sec on commodity SSD) sits well above the audiences' realistic write rates. Synchronous writes give the cleanest audit-is-canonical story; async-batched is a known fallback path when benchmarks justify it. The composability story (peer audit infrastructure via JSONL) handles the cases beyond Locksmith's scale envelope without absorbing audit-store functionality into Locksmith itself.

---

*End of Phase 1 artifacts (extended by Phase 2 codebase findings: INF-23..INF-25).*

---

*End of Phase 2 codebase findings. Phases 3–7 to follow.*
