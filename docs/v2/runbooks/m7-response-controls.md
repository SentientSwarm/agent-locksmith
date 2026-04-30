# M7 — Response Controls Runbook

**Audience:** operators bounding the response surface of LLM and tool upstreams, and engineers verifying the M7 acceptance contract before merging to `develop`.

**Covers:** per-tool `max_size_bytes`, `content_type_allowlist`, `redaction_patterns`. Streaming preservation (R-N6 first-byte ≤100ms). Composition with D-18 (LlamaFirewall and similar in-process scanners).

---

## 1. M7 acceptance checklist

| Criterion | Source | Verified by |
|-----------|--------|-------------|
| `tools[].response` block parses (max_size_bytes, content_type_allowlist, redaction_patterns) | T7.1 | `tests/response_controls_config_test.rs` (4 tests) |
| Invalid regex fails config load | T7.1 | `tests/response_controls_config_test.rs::invalid_redaction_regex_fails_config_load` |
| Duplicate pattern id fails config load | T7.1 | `tests/response_controls_config_test.rs::duplicate_pattern_id_fails_config_load` |
| `ResponseControls.apply_non_streaming` passes through / size-rejects / content-type-rejects / redacts | T7.2 | `tests/response_controls_apply_test.rs` (10 tests) |
| Hash recorded never contains cleartext | T7.4 | `tests/response_controls_apply_test.rs::redaction_replaces_match_with_default_marker` + `redaction_test::pattern_match_redacts_response_body_and_records_hash` |
| Streaming under cap unchanged | T7.3 | `tests/response_controls_size_test.rs::streaming_under_cap_passes_unchanged` |
| Streaming over cap emits truncation marker | T7.3 | `tests/response_controls_size_test.rs::streaming_over_cap_emits_truncation_marker` |
| Streaming truncation emits `response_size_exceeded` audit row | T7.4 | `tests/response_controls_size_test.rs::streaming_truncation_emits_audit_row` |
| Non-streaming over cap → 502 with `response_size_exceeded` body | T7.2 | `tests/response_controls_size_test.rs::nonstreaming_over_cap_returns_502` |
| Disallowed content-type → 502 + audit row | T7.2 | `tests/response_controls_content_type_test.rs::rejected_content_type_returns_502_with_audit` |
| `application/json; charset=utf-8` matches `application/json` allowlist | T7.2 | `tests/response_controls_content_type_test.rs::allowed_content_type_passes_with_charset_suffix` |
| Pattern match → redacted body + audit `response_redaction` with hash | T7.4 | `tests/response_controls_redaction_test.rs::pattern_match_redacts_response_body_and_records_hash` |
| M1 streaming first-byte ≤100ms preserved with response controls active | regression | `tests/streaming_passthrough_test.rs` (3 tests, run as part of full suite) |
| `cargo clippy --all-targets -- -D warnings` clean | engineering std | local CI mirror |
| `cargo fmt --check` clean | engineering std | local CI mirror |

---

## 2. Choosing controls

The three controls are independent. Combine as you see fit per tool.

| Control | Use when | Trade-off |
|---------|----------|-----------|
| `max_size_bytes` | Upstream is untrusted (or trusted but flaky); you need to bound resource use | Streaming truncates with a marker; non-streaming returns 502. Agents that don't tolerate truncation should consume the marker. |
| `content_type_allowlist` | Upstream is contracted to JSON / SSE; HTML or plaintext indicates a misbehaving response (auth-redirect page, stack trace) | Off-contract responses turn into 502 the agent can retry on. |
| `redaction_patterns` | You suspect upstream may leak secrets (its own keys reflected in errors, customer PII in debugging output) | **Forces the buffered (non-streaming) path** for that tool. Streaming flows lose ≤100ms first-byte latency. Use D-18 (LlamaFirewall) for streaming inspection. |

### Composition with D-18 (post-v2)

Redaction is regex, not DLP. It catches what you tell it to catch — known-shape secrets like API keys, AWS access keys, SSNs. For semantic / intent-level scanning use a streaming-friendly classifier (LlamaFirewall etc.) layered on top per D-18. v2 doesn't ship the classifier integration; the boundary is "M7 stops the obvious leaks; D-18 stops the subtle ones."

---

## 3. Streaming vs buffered path — the dispatch rule

The proxy hot path picks one of two flows per request based on the tool's response config:

```
if rc.has_redaction_patterns():
    → buffered: read full body, apply redaction, return non-streaming
else:
    → streaming with optional size-cap wrapper (M0..M6 default + cap)
```

If you need redaction AND streaming (e.g. SSE token stream), do NOT use `redaction_patterns` — instead compose with D-18 in front. The runbook deliberately doesn't try to mix the two modes; the SPEC §6.2 / T7.3 contract is "streaming flows preserved (only total-size cap applies to streaming)."

---

## 4. Configuration recipes

### 4.1 Bound LLM token streams to 5 MB

```yaml
tools:
  - name: openai
    upstream: "https://api.openai.com"
    response:
      max_size_bytes: 5242880        # 5 MiB
```

Streaming SSE under 5 MB passes through unchanged. Over 5 MB, the stream is cut at 5 MB and a `\n{"_locksmith":"response_size_exceeded"}\n` marker is appended. Audit records cap + observed bytes.

### 4.2 Reject HTML responses from a contracted JSON API

```yaml
tools:
  - name: weather
    upstream: "https://api.openweathermap.org"
    response:
      max_size_bytes: 524288         # 512 KiB
      content_type_allowlist: ["application/json"]
```

If the upstream returns `text/html` (login page, error page, IP-blocked page), the proxy returns 502 with `response_content_type_disallowed`. The agent gets a clean signal it's not a transient upstream blip.

### 4.3 Redact known secret shapes from a chatty backend

```yaml
tools:
  - name: internal-api
    upstream: "https://internal.example.com"
    response:
      max_size_bytes: 1048576
      content_type_allowlist: ["application/json", "text/plain"]
      redaction_patterns:
        - id: openai_key
          regex: 'sk-[A-Za-z0-9]{20,}'
        - id: aws_secret
          regex: 'AKIA[A-Z0-9]{16}'
        - id: ssn
          regex: '\d{3}-\d{2}-\d{4}'
          replacement: '[SSN-REDACTED]'
```

Audit emits one `response_redaction` row per pattern that matched, with `pattern_id`, `matches` count, and `match_hash` (SHA-256 hex of cleartext matches). **Cleartext is never recorded.**

---

## 5. Audit events

Three new event types under `event_class=proxy`:

| Event | Decision | Trigger |
|-------|----------|---------|
| `response_size_exceeded` | denied | Body bytes > `max_size_bytes` (streaming or non-streaming flow) |
| `response_content_type_disallowed` | denied | Upstream content-type not in `content_type_allowlist` |
| `response_redaction` | allowed | Per-pattern: matches > 0; one event per pattern, includes `pattern_id` + `matches` + `match_hash` |

All carry `auth_method=bearer` (M2 default; M6 mTLS deployments populate `mtls`).

Filter by event:

```bash
locksmith audit query --event response_redaction --format json | jq
locksmith audit query --event response_size_exceeded --since-ms <yesterday> --format json
```

---

## 6. Verifying M7 end-to-end

From the repo root:

```bash
# Unit + apply tests
cargo test --test response_controls_config_test
cargo test --test response_controls_apply_test
cargo test --test response_controls_streaming_test

# Integration (daemon-driven)
cargo test --test response_controls_size_test
cargo test --test response_controls_content_type_test
cargo test --test response_controls_redaction_test

# M1 streaming regression — must still report 3/3 ok
cargo test --test streaming_passthrough_test
```

For a manual smoke against a real deployment with a streaming upstream:

```bash
time curl -N http://localhost:9200/api/openai/v1/chat/completions \
    -H 'Authorization: Bearer lk_...' \
    -H 'Content-Type: application/json' \
    -d '{"model":"gpt-4","stream":true,"messages":[{"role":"user","content":"hi"}]}'

# First byte should arrive within ~100ms of upstream first byte. Confirm
# the SSE stream completes (no marker line) when output stays under cap.
```

---

## 7. Common errors

| Symptom | Diagnosis | Fix |
|---------|-----------|-----|
| Config fails to load with `regex compile failed` | A `redaction_patterns[].regex` is malformed | Test the regex with `rg --pcre2-version` or `cargo run -- ...` and fix |
| Config fails with `duplicate redaction_patterns id` | Two patterns share an `id` | Rename one |
| All requests return 502 with `response_content_type_disallowed` | Upstream's content-type isn't in your allowlist | Add it, or remove the allowlist |
| Streaming SSE truncates unexpectedly | `max_size_bytes` is smaller than the longest expected response | Raise the cap or drop it for that tool |
| Audit row contains the secret's match hash but I want the cleartext | By design — cleartext is never recorded | Use upstream-side logging if you genuinely need cleartext (rare; usually a sign the redaction shouldn't fire) |
| First-byte latency >100ms after enabling response controls | Tool has `redaction_patterns` set ⇒ buffered path | Move redaction out to D-18 (LlamaFirewall) for that tool; keep size-cap + content-type only in `response:` |

---

## 8. What M7 does not include

- **Streaming-aware regex redaction.** Buffered redaction would defeat R-N6 first-byte latency. Use D-18 instead.
- **Per-pattern actions** beyond replace (e.g. block-on-match, alert-on-match). Match counts in audit are the signal; alerting is downstream.
- **DLP-grade content classification.** This is regex on bytes. Semantic redaction is a separate product (D-18 again).
- **Outbound-request redaction.** M7 only constrains responses. Request-side controls already exist via `body_limit_bytes` (M1) and the per-tool auth header strip (M0).

---

*M7 closes the response-side hole that M1's streaming proxy left open. v2 is feature-complete with this milestone.*
