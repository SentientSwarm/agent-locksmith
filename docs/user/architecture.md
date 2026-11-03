# Architecture (user-level)

How agent-locksmith composes at runtime — the user-level mental model
of what happens when you start the daemon and send it a request.

For the engineering view (every task, every callsite),
see [`docs/v2/SPEC.md`](../v2/SPEC.md).

OAuth exchanges persist against a non-reused incarnation and token version;
late results cannot overwrite a replacement or return uncommitted credentials.
Revoke invalidates pending writers without waiting for their network lock.
See the [custody contract](../development/oauth-custody.md) and
[recovery/0010 upgrade](operator/oauth-recovery.md); crash-safe rotation remains separate.

## The daemon

`locksmithd` runs one process with two concurrent surfaces:

```
                  ┌─────────────────────────────────────────┐
                  │                                         │
                  │   Agent listener (TCP)                  │
   agent ──HTTPS──┤   :9200 (default)                       │
   bearer/mtls    │   • /api/{tool}/{*path}  proxy hot path │
                  │   • /tools, /models       discovery     │
                  │   • /skill                personalised  │
                  │   • /livez, /readyz       health probes │
                  │                                         │
                  │   Admin listener (UDS)                  │
   operator ──UDS─┤   /var/run/locksmith/admin.sock         │
   bearer         │   • /admin/operator/{agents, bootstrap_tokens, tools, models, infra, oauth, audit}
                  │   • /admin/agent/{status, rotate, register, deregister, tools}
                  │                                         │
                  │   Optional: admin HTTPS (M4)            │
                  │                                         │
                  └─────────────────────────────────────────┘
```

Both listeners share one process, one SQLite pool, one audit fanout.

## The agent's request flow

When an agent calls `POST /api/anthropic/v1/messages` with
`Authorization: Bearer lk_...`:

```
1. axum routes the request to proxy::proxy_handler
   ↓
2. auth::auth_middleware validates the bearer
     against AgentRepository (BearerAuthenticator).
     Stamps AgentIdentity into request extensions.
     Failure → 401 invalid_credential
   ↓
3. M9 ACL gate: identity.allows_tool(name)
     Failure → 403 tool_not_allowed + audit row
   ↓
4. Current HTTP admission (DB-backed):
     Read agent lifecycle, reviewed finite grants, registration and selection
     in one SQLite snapshot. Missing/null/unreviewed policy grants nothing.
     Missing/disabled registration → 404; never fall through to YAML.
     Persisted/runtime registration mismatch → 503 connection_not_active.
   ↓
5. Explicit account admission:
     Missing selection → 403 tool_not_allowed; audit account_binding_missing.
     Use only this snapshot's selected binding, never the template.
     Unavailable selected source → 503; no upstream dispatch.
     For selected OAuth, require a nonempty session label and consistent
     metadata across bindings sharing that registration/label.
     Resolve that session; missing/degraded/unsealable → safe 503.
     Expired access token → inline refresh under the session lock.
   ↓
6. Header strip: agent's Authorization, x-api-key, host
     plus the target's own auth header (defense-in-depth).
   ↓
7. Credential injection from the selected binding only:
     None     → nothing (explicit operator choice).
     Header/Bearer → resolve selected environment/stored/1Password reference.
     OAuth    → selected session's access token.
   ↓
8. Egress route:
     egress: proxied  → HTTP CONNECT through pipelock
     egress: direct   → straight to upstream
   ↓
9. Stream the response back to the agent.
   ↓
10. Apply M7 response controls if configured:
      max_size_bytes, content_type_allowlist, redaction_patterns.
   ↓
11. Emit one AuditEvent → SQLite + (optional) JSONL mirror.
```

Steps 1–11 happen per request. The audit row is the operator's
single source of truth for who-called-what-when. `/tools`, `/models` and
personalized `/skill` show current finite eligibility and runtime activation.
They can report `account_selected`, but never attest source health. A saved
admin write whose refresh fails reports failure/pending and denies the affected
route; unrelated matching routes remain usable. Config-only discovery is labelled
`configuration_only`. Already-admitted requests may finish after authority changes;
new admissions use current persisted state. Identityless legacy requests require `auth: none`; they
cannot consume a credentialed registration default. See
[explicit account bindings](changes/explicit-account-bindings.md) for repair.

## Composition root: `daemon::run`

`src/daemon.rs::run` is the only place where state gets wired up.
Read it first if you're contributing code. It does (in order):

1. Parse + validate `AppConfig`.
2. Construct `Arc<ArcSwap<AppConfig>>` so config can hot-reload.
3. Resolve `tool.auth.value: SecretRef` for legacy config.tools entries
   (env vars + sealed files + Vault/AWS stubs).
4. **Build admin substrate** (only when `listen.admin_socket` is set):
   - Open SQLite pool, run migrations.
   - Construct repositories (AgentRepository, BootstrapTokenRepository,
     AuditRepository, RegistrationRepository, OauthSessionRepository).
   - Run **seed loader** (Phase E.7) — populate registrations from
     `/etc/locksmith/seed/catalog.yaml`.
   - Run **legacy_bootstrap** — migrate any pre-Phase-E `config.tools`
     entries into the registrations table with `seed=false`.
   - Build the in-memory `Catalog` cache from the registrations table.
   - Resolve registration env vars into the resolved_creds map.
   - **Build OAuth runtime** (when `LOCKSMITH_OAUTH_SEALING_KEY` is set):
     `OauthSessionRepository`, `RefreshLockMap`, spawn the background
     refresh task.
   - Construct `AdminService` + `BearerAuthenticator` +
     `OperatorAuthenticator`.
5. Spawn the **audit retention sweeper** (T3.5).
6. Bind agent listener (TCP for bearer, TLS for mTLS).
7. Bind admin UDS listener.
8. Optionally bind admin HTTPS listener.
9. Optionally bind bootstrap-only listener (M6 / C-4).
10. Wait for SIGTERM/SIGINT; shut down both listeners within the drain window.

## State that survives restarts

Anything that needs to outlive `locksmithd` lives in the SQLite DB:

```
locksmith.db
├── agents              — identity + finite reviewed ACL + expiry/revocation
├── bootstrap_tokens    — pre-issued enrollment tokens
├── audit               — every request + admin write
├── registrations       — kind-discriminated catalog (Phase E)
├── agent_credential_overrides — explicit per-agent selected source references
├── registrations_meta  — seed version + migration receipt/revision bookkeeping
└── oauth_sessions      — sealed OAuth tokens (Phase F)
```

The audit table can also mirror to a JSONL file (rotating, size-capped)
so the audit log survives volume recreation.

## What's transient (in-memory only)

- `resolved_creds` — `Arc<ArcSwap<HashMap<String, SecretString>>>`.
  Built at startup from env vars + sealed files. Refreshed when an
  admin write touches a registration.
- `Catalog` — `Arc<ArcSwap<Catalog>>`. In-memory mirror of the
  registrations table. Refreshed by admin writes.
- `OauthRuntime` — sealing key + session repo + refresh lock map +
  shared HTTP client.
- `ResponseControls` cache — compiled regex patterns per tool.
- `ClientPool` — cached `reqwest::Client` per (name, timeouts, egress).

## Auth surfaces are independent

Three auth surfaces, each picks its own mode:

| Surface | Modes | Notes |
|---|---|---|
| Agent listener | `bearer \| mtls \| both` | `listen.auth_mode` |
| Admin UDS | bearer only | OS peer-uid is the gate |
| Admin HTTPS (optional) | `bearer \| mtls \| both` | `listen.admin_https.auth_mode` |

You can run agents on bearer + admin HTTPS on mTLS, or vice versa.
The settings are independent.

## What stays the same as v1.x → v2.0.0

- The §4.7.9 wire envelope shape:
  `{"error": {"type": "...", "code": "...", "message": "..."}}`.
- Existence-leak avoidance (Q-8): admin errors don't reveal whether
  a name exists; agent errors are generic.
- `M5 secret resolution` — sealed-file, Vault, AWS stubs continue to
  exist for config-only paths; DB-backed routes do not use YAML fallback.
- `M7 response controls` — size cap, content-type allowlist, regex
  redaction. Apply uniformly across catalog and legacy paths.
- Audit shape (additive `auth_mode` + `oauth_session_id` fields).

## See also

- [`getting-started.md`](getting-started.md) — first-contact.
- [`cli-reference.md`](cli-reference.md) — every subcommand.
- [`concepts/`](concepts/) — kind taxonomy, agent identity + ACL,
  trust boundary, error envelope.
- [`docs/v2/SPEC.md`](../v2/SPEC.md) — engineering spec with task
  references (T1.x, T2.x, …).
- [`agents-stack/docs/spec/v0.2.0.md`](https://github.com/SentientSwarm/agents-stack/blob/main/docs/spec/v0.2.0.md)
  — formal stack spec.
