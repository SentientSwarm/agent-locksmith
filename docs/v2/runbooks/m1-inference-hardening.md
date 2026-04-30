# M1 — Inference-Ready Hardening Runbook

**Audience:** operators upgrading from M0 to M1, and engineers verifying the M1 acceptance contract before merging to `develop`.

**Covers:** verification procedures for T1.1–T1.13, the M0 → M1 config migration, the new `/livez` / `/readyz` / `/version` endpoints, and the SIGTERM drain behavior.

---

## 1. M1 acceptance checklist

Tick every item before claiming M1 done. The last column shows where each criterion is verified.

| Criterion | Source | Verified by |
|-----------|--------|-------------|
| SSE/streaming responses pass through to the agent without buffering | R-F12, R-N6 | `tests/streaming_passthrough_test.rs` (3 tests) |
| First-byte latency ≤100ms over upstream first-byte | R-N6 | `test_sse_first_byte_within_100ms_of_upstream` |
| Inter-chunk gaps preserved (no buffering between chunks) | R-N6 | `test_chunk_intervals_preserved` |
| Long-running streams complete | R-F12 | `test_long_running_stream_completes` |
| Per-tool timeouts (request + idle) configurable | R-F12 | `tests/config_strict_test.rs::test_per_tool_timeouts_parse` |
| Per-tool body-limit configurable | R-F12 | `tests/config_strict_test.rs::test_per_tool_timeouts_default_when_omitted` |
| `cloud:` field renamed to `egress:` with backwards-compat shim | R-F13, INF-15 | `test_legacy_cloud_true_maps_to_egress_proxied` |
| Strict-config rejects unknown fields | INF-17 | `test_unknown_top_level_field_rejected` |
| One-shot deprecation warnings (no log flooding) | INF-24 | `tests/deprecation_test.rs::test_renamed_field_warns_once_per_registry` |
| Per-tool reqwest client pool with hot-reload eviction primitive | INF-25 | `src/client_pool.rs` unit tests (4) |
| SIGTERM + SIGINT graceful drain | INF-1 | `src/shutdown.rs` unit tests (4) |
| `/livez`, `/readyz`, `/version` endpoints (k8s-style) | INF-3 | `tests/health_test.rs` (7) |
| `/health` preserved as backward-compat alias to `/livez` | M0 compat | `test_health_alias_to_livez_for_backward_compat` |
| Structured token type (`lk_<id>.<secret>`) ready for M2 | INF-5 | `src/token.rs` unit tests (8) |
| Local-upstream inference matrix passing | M1 acceptance | `tests/inference_matrix_local_test.rs` |
| Cloud-provider matrix passes pre-PR | Q-2 | `tests/inference_matrix_cloud_test.rs` (run with keys) |
| `cargo clippy --all-targets -- -D warnings` clean | engineering std | local CI mirror |
| `cargo fmt --check` clean | engineering std | local CI mirror |

---

## 2. Verifying streaming passthrough

The load-bearing M1 test. Run from the repo root:

```bash
cargo test --test streaming_passthrough_test
```

Expected: 3 tests pass within ~5s. The longest test is `test_long_running_stream_completes` (~5s simulated upstream).

If a test fails with `hyper::Error(IncompleteMessage)`, the streaming passthrough is broken — see `src/proxy.rs` for the change point. M0 had two intertwined defects (body buffering + chunked-TE/flat-body framing mismatch) that both manifest as IncompleteMessage; T1.2's `Body::from_stream(resp.bytes_stream())` resolves both.

If a test fails with `first byte arrived after Xms, expected < 100ms`: profile the proxy. Likely culprits: a buffering middleware accidentally added; TLS handshake on a cold pool entry (warm-up before measuring); or hyperscaler infrastructure between agent and proxy adding buffering.

---

## 3. Running the local-upstream matrix

```bash
cargo test --test inference_matrix_local_test
```

The fixture test always runs. Ollama / LM Studio tests skip when their hosts are unreachable; output looks like:

```
test fixture_streams_chat_completion_through_locksmith ... ok
test ollama_streams_chat_through_locksmith_when_present ... ok
SKIP: ollama not reachable at localhost:11434; set OLLAMA_HOST to enable
test lmstudio_streams_chat_through_locksmith_when_present ... ok
SKIP: LM Studio not reachable at localhost:1234; set LMSTUDIO_HOST to enable
```

To exercise Ollama or LM Studio:

1. Install and start the service (`ollama serve` or LM Studio's local server).
2. Optionally pull a small model (Ollama: `ollama pull llama3.2:1b`).
3. Re-run the test. If the host is reachable, the test routes a probe request through Locksmith and asserts the response forwards correctly.

Override the host via env var:

```bash
OLLAMA_HOST=192.168.1.10:11434 cargo test --test inference_matrix_local_test
```

---

## 4. Running the cloud-provider matrix (local-only, Q-2)

These tests are **excluded from default CI** per Q-2 (PRD §14.1 #2). Engineers run them pre-PR with their own credentials. Cost per run is ≪ $0.001 (cheapest model + ≤4 output tokens).

```bash
ANTHROPIC_API_KEY=sk-ant-... \
OPENAI_API_KEY=sk-... \
cargo test --test inference_matrix_cloud_test
```

Without the env vars, the tests skip:

```
SKIP: ANTHROPIC_API_KEY not set; export it locally to run this test
SKIP: OPENAI_API_KEY not set; export it locally to run this test
```

PR descriptions should note: "Tested locally with both ANTHROPIC_API_KEY and OPENAI_API_KEY" when the change touches anything in `src/proxy.rs` or `src/client_pool.rs`.

---

## 5. Migrating from `cloud:` to `egress:`

The M0 `cloud: bool` field per tool entry has been replaced by `egress: direct | proxied` (R-F13). The deprecation registry (INF-24) translates the legacy field with a one-shot warning per process.

**Old (M0):**
```yaml
tools:
  - name: github
    upstream: https://api.github.com
    cloud: true
    timeout_seconds: 30
```

**New (M1):**
```yaml
tools:
  - name: github
    upstream: https://api.github.com
    egress: proxied
    timeouts:
      request_seconds: 30
      idle_seconds: 60
    body_limit_bytes: 10485760
```

Translation rules (applied at config load):

| Legacy | New | Behavior |
|--------|-----|----------|
| `cloud: true` | `egress: proxied` | One-shot WARN log; subsequent loads silent. |
| `cloud: false` | `egress: direct` | Same. |
| `timeout_seconds: N` | `timeouts.request_seconds: N` | One-shot WARN log; idle_seconds takes its default (60). |
| `telemetry: { ... }` | (removed) | One-shot WARN log; field dropped entirely. M0's TelemetryConfig was dead code; OTel deferred per Q-19. |

**When you see a deprecation warning, the deployment still works** — the legacy field is interpreted. But the warning calls out the rename so you can update the file at your convenience. The `cloud:` deprecation is scheduled for removal in v0.3.0; both fields work in v0.2.x.

**Disagreement handling:** if both old and new fields are present and disagree (e.g., `cloud: false` and `egress: proxied`), the explicit new field wins.

---

## 6. Verifying graceful shutdown (INF-1)

M0 only handled SIGINT (Ctrl-C). M1 also handles SIGTERM (the signal systemd sends on `systemctl stop`) and waits up to `shutdown.drain_window_seconds` (default 30) for in-flight requests.

Verify locally:

```bash
# Terminal 1: start a Locksmith with a small drain window for quick observation.
cat > /tmp/locksmith.yaml <<'EOF'
listen: { host: 127.0.0.1, port: 9200 }
shutdown: { drain_window_seconds: 5 }
tools: []
EOF
cargo run -- --config /tmp/locksmith.yaml

# Terminal 2: send SIGTERM.
pkill -TERM -f locksmith

# Terminal 1 should log:
#   INFO Shutdown signal received; draining listeners
#   INFO clean shutdown complete
```

For long-running streams:

```bash
# Terminal 2: start a streaming request through the proxy (e.g., 10s upstream).
# Terminal 3: pkill -TERM -f locksmith
# The streaming request should COMPLETE if it finishes within drain_window_seconds.
# If not, the listener closes and the agent sees a truncated response.
```

---

## 7. M0 → M1 health-endpoint changes

M0's `/health` returned a JSON body with `{ status, uptime_seconds, tools, version }`. M1 splits this into k8s-style endpoints:

| Endpoint | Body shape | Auth | Role |
|----------|-----------|------|------|
| `/livez` | `{ status: "live", uptime_seconds }` | None | systemd readiness, k8s livenessProbe |
| `/readyz` | `{ status: "ready" \| "not_ready", reason?, tools? }` | None | k8s readinessProbe; 503 when any tool's credential is unresolved |
| `/version` | `{ version, name }` | None | Incident response |
| `/health` | Alias to `/livez` (200 + body) | None | M0 compat — existing systemd / Ansible probes keep working |

Operators using `/health` for HTTP-200 probes need no changes. Operators parsing the body should switch to `/livez` (matches the `/health` body shape exactly) and add `/readyz` polling if they want degraded-mode awareness.

`/readyz` semantics in M1: returns 200 only when every tool that declares an `auth` block has a non-empty resolved credential. M2 introduces per-tool `on_secret_failure: degraded` (INF-4 / Q-17) to opt out of the readiness check.

---

## 8. Verification command summary

```bash
# Lint and format. CI runs the first; local-dev should match.
cargo clippy --all-targets -- -D warnings
cargo fmt --check

# Default CI lane: all tests except cloud-provider matrix.
cargo test --tests

# Pre-PR full matrix:
ANTHROPIC_API_KEY=... OPENAI_API_KEY=... cargo test --tests

# Targeted M1 acceptance:
cargo test --test streaming_passthrough_test
cargo test --test inference_matrix_local_test
cargo test --test config_strict_test
cargo test --test health_test
cargo test --test deprecation_test
```
