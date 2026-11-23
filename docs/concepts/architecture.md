# Architecture (user-level)

How agent-locksmith composes at runtime — the user-level mental model
of what happens when you start the daemon and send it a request.

The historical 2.x engineering spec, which explains old task tags, is
[`docs/archive/v2/SPEC.md`](../archive/v2/SPEC.md); it is not current.

OAuth exchanges persist against a non-reused incarnation and token version;
late results cannot overwrite a replacement or return uncommitted credentials.
Revoke invalidates pending writers without waiting for their network lock.
See the [custody contract](../development/oauth-custody.md) and
[recovery/0010 upgrade](../operator/oauth-recovery.md); crash-safe rotation remains separate.

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
     Optional per-binding upstream method policy is read in that same snapshot.
     Deny wins; unlisted/nonliteral methods return 403 method_not_allowed
     before resolving credentials or dispatch. Absent policy is unrestricted.
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
     egress: proxied  → egress.mode pipelock (default when egress_proxy
                        is set): through the egress proxy; https
                        upstreams tunnel via CONNECT, http upstreams
                        are sent as absolute-form requests.
                        egress.mode external: straight to upstream; the
                        surrounding infrastructure enforces egress.
                        Neither configured: 503 egress_proxy_unconfigured
                        and an egress_unenforced security audit event.
     egress: direct   → straight to upstream
   ↓
9. Stream the response back to the agent.
   ↓
10. Apply M7 response controls if configured:
      max_size_bytes, content_type_allowlist, redaction_patterns.
   ↓
11. Emit one AuditEvent → SQLite + (optional) JSONL mirror.
```

See [egress and inspection](egress-and-inspection.md) for what
each egress mode enforces and what content inspection can and cannot catch.

Steps 1–11 happen per request. The audit row is the operator's
single source of truth for who-called-what-when. `/tools`, `/models` and
personalized `/skill` show current finite eligibility and runtime activation.
They can report `account_selected`, but never attest source health. A saved
admin write whose refresh fails reports failure/pending and denies the affected
route; unrelated matching routes remain usable. Config-only discovery is labelled
`configuration_only`. Already-admitted requests may finish after authority changes;
new admissions use current persisted state. There are no identityless
requests: legacy mode was removed in 3.0.0 (AGENT-297). See
[explicit account bindings](../changes/explicit-account-bindings.md) for repair.

## Composition root: `daemon::run`

`src/daemon.rs::run` is the only place where state gets wired up.
Read it first if you're contributing code. It does (in order):

1. Parse + validate `AppConfig`. Refuse a config without
   `listen.admin_socket`, `database.path` or `operator_credentials_path`
   before taking the state lock (legacy mode was removed in 3.0.0).
2. Construct `Arc<ArcSwap<AppConfig>>`, the one config snapshot the agent
   router and AdminService share. The YAML file is read once, at startup;
   see [Changing configuration](#changing-configuration).
3. Resolve `tool.auth.value: SecretRef` for legacy config.tools entries
   (env vars + sealed files + Vault/AWS stubs).
4. **Build admin substrate**:
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

## Changing configuration

Locksmith reads its YAML config file and `operator_credentials_path` once, at
startup. There is no `SIGHUP` handler and no `config reload` command. To apply
an edit to either file, restart `locksmithd`. Startup validates the whole file
(`deny_unknown_fields`) and refuses to start on any error, so check a changed
file on a disposable instance or keep the previous copy to roll back.

Everything held in the database changes live through the admin API (CLI over
the admin socket or admin HTTPS), with no restart:

- tools, models and infra registrations (`locksmith tool|model|infra`);
- agents, bootstrap tokens, ACLs, grants and account bindings;
- per-agent and operator credentials, OAuth sessions and consent;
- integration definitions and native MCP review.

Two files the daemon re-reads on its own: the `listen.mtls.blocklist_path`
file (every `blocklist_reload_interval_seconds`) and the CRL from
`listen.mtls.crl_url` (every `crl_refresh_interval_seconds`). Their paths,
and every TLS certificate and key, still need a restart to change.

Legacy `config.tools` entries are migrated into the registrations table at
startup. After that, manage those tools through the admin API; an edit to
`config.tools` does not change an existing registration.

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

- [`getting-started.md`](../getting-started.md) — first-contact.
- [`cli-reference.md`](../reference/cli-reference.md) — every subcommand.
- [`operator/edge-packaging.md`](../operator/edge-packaging.md) — systemd
  units in Incus containers, rendered from a private site file.
- [`concepts/`](./) — kind taxonomy, agent identity + ACL,
  trust boundary, error envelope.
- [`docs/archive/v2/SPEC.md`](../archive/v2/SPEC.md) — historical 2.x spec;
  explains task references (T1.x, T2.x, …).

## Binding method policy (AGENT-339)

The operator owns optional upstream method policies; the daemon stores them in
SQLite alongside explicit bindings and reads them at admission. Changes through
the [operator CLI/API](../reference/cli-reference.md#upstream-method-policy)
apply live. Credential replacement preserves a policy, while deleting a binding
removes it. Existing routes have no policy after upgrade. No new process or
network connection is involved. See [ADR-0001](../adr/0001-binding-method-policy.md)
for the contract and tradeoffs. This scoped description is based on
`agent-locksmith@031c742` plus the AGENT-339 change on this branch.

## Slack workspace credential ingestion (AGENT-340)

An HTTP tool can declare `metadata.slack_team_id` (`tool put --slack-team-id`).
Route and per-agent sealed bearer writes then verify `auth.test` before storing
the token, using the route's egress and CA policy. Refusals preserve the prior
key. The immutable expectation belongs to the route, while the credential
selection still belongs to the binding. See the [scoped architecture](slack-workspace-architecture.md)
and [ADR-0002](../adr/0002-slack-workspace-ingestion.md) for the contract, race
boundary and limits. D-001 remains responsible for the broader Slack model.
