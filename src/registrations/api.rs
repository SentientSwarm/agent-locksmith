//! Phase E.3 — admin endpoints + public discovery (/tools, /models).
//!
//! Two surfaces:
//!
//! - **Admin (operator-credential-authed):**
//!   `GET/PUT/DELETE/list /admin/operator/{tools,models,infra}/<name>` and
//!   `POST /admin/operator/{tools,models,infra}/<name>/enable`.
//!   Mounted under the existing operator router in `src/admin/uds.rs`.
//!
//! - **Public discovery (per-agent-bearer-authed, ACL-filtered):**
//!   `GET /tools` (kind=tool only) + `GET /models` (kind=model only).
//!   `kind=infra` has no agent-facing endpoint.
//!
//! All errors render through the §4.7.9 envelope (extends the existing
//! AuthError envelope with new codes — see `RegistrationError` arm
//! mapping below).

use crate::auth_v2::AgentIdentity;
use crate::registrations::{
    AuthSpec, Kind, Registration, RegistrationError, RegistrationRepository, validate_name,
};
use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use secrecy::ExposeSecret;
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

// ─── Public discovery helpers ───────────────────────────────────────────────

/// Render a public discovery list (`GET /tools` or `GET /models`).
/// Filters to the requested kind, drops `disabled=true` rows, applies the
/// agent's ACL via [`AgentIdentity::allows_tool`], and emits the minimal
/// agent-facing JSON shape — name + path + description, no auth shape, no
/// upstream URL or private metadata. Only validated http_service is projected.
pub async fn list_public(
    repo: &RegistrationRepository,
    catalog: &crate::registrations::Catalog,
    kind: Kind,
    identity: Option<&AgentIdentity>,
) -> Result<Vec<Value>, RegistrationError> {
    let Some(identity) = identity else {
        return Ok(Vec::new());
    };
    let mut rows = repo
        .http_admissions(identity, None)
        .await
        .map_err(|_| RegistrationError::Backend("admission state unavailable".into()))?;
    if kind == Kind::Tool {
        rows.extend(
            repo.native_admissions(identity, None)
                .await
                .map_err(|_| RegistrationError::Backend("admission state unavailable".into()))?,
        );
    }
    Ok(rows
        .into_iter()
        .filter(|r| r.discoverable(kind, catalog))
        .map(|r| {
            let mut value = json!({
                "name": r.registration.name,
                "type": if r.registration.protocol == super::Protocol::Http {"api"} else {"mcp"},
                "path": format!("/{}/{}", if r.registration.protocol == super::Protocol::Http {"api"} else {"mcp"}, r.registration.name),
                "description": r.registration.description,
                "activation": "active",
                "account_selected": r.account.is_some(),
                "credential_readiness": "not_checked",
            });
            if r.registration.protocol == super::Protocol::McpStreamableHttp {
                value["protocol_version"] = super::protocol::VERSION.into();
                value["tool_authority"] = "reviewed_per_agent".into();
                if r.registration.mcp.as_ref().is_some_and(|c| c.compact) {
                    value["compact_path"] = format!("/mcp/{}/compact", r.registration.name).into();
                }
            }
            if let Ok(Some(service)) = super::http_service::from_metadata(&r.registration.metadata)
            {
                value["http_service"] = json!(service);
            }
            value
        })
        .collect())
}

// ─── Admin endpoint payloads ────────────────────────────────────────────────

/// PUT body for `/admin/operator/<kind>/<name>`. Lifecycle fields
/// (seed/disabled/timestamps) are server-managed; not accepted from the
/// operator. Cross-kind name reuse is enforced server-side by checking the
/// existing row's kind against the URL path's kind.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PutBody {
    #[serde(default)]
    pub protocol: super::Protocol,
    #[serde(default)]
    pub mcp: Option<super::McpConfig>,
    /// Optional. Defaults to empty string.
    #[serde(default)]
    pub description: String,
    pub upstream: String,
    /// `kind=tool` requires this field present (use `auth: "none"` for
    /// authless). `kind=model` rejects `none`. `kind=infra` may omit.
    /// Implicit absence is the footgun we close at v2.0.0 — the
    /// `Option` here represents "field literally missing in JSON",
    /// distinct from `Some(AuthSpec::None)` which is "operator stated none".
    #[serde(default)]
    pub auth: Option<AuthSpec>,
    /// "direct" | "proxied". Defaults to "proxied".
    #[serde(default)]
    pub egress: Option<crate::config::EgressMode>,
    #[serde(default)]
    pub timeouts: Option<crate::config::ToolTimeouts>,
    #[serde(default)]
    pub body_limit_bytes: Option<u64>,
    #[serde(default)]
    pub metadata: Option<Value>,
}

/// Phase J (ADR-0008) — body for `PUT /admin/operator/<kind>/<name>/credential`.
/// The single `value` field is the cleartext credential to seal + store.
/// Reveal-never (CCS-1): the value is sealed with the credential sealing
/// key before it hits the `credential_secrets` store; it is never logged,
/// echoed in the response, or persisted in cleartext. `deny_unknown_fields`
/// rejects any accidental extra fields (e.g. a stray `secret_ref`).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PutCredentialBody {
    /// Zeroized on drop; exposed only for the instant it is sealed.
    pub value: secrecy::SecretString,
}

/// Render a `Registration` as the admin-facing JSON. Operators see
/// everything including the auth shape (env-var name only — never the
/// resolved cleartext) and lifecycle flags.
pub fn registration_to_admin_json(r: &Registration) -> Value {
    json!({
        "name": r.name,
        "protocol": r.protocol,
        "mcp": r.mcp,
        "kind": r.kind,
        "description": r.description,
        "upstream": r.upstream,
        "auth": r.auth,
        "egress": r.egress,
        "timeouts": r.timeouts,
        "body_limit_bytes": r.body_limit_bytes,
        "metadata": r.metadata,
        "seed": r.seed,
        "disabled": r.disabled,
        "created_at": r.created_at,
        "updated_at": r.updated_at,
    })
}

// ─── Error envelope rendering ───────────────────────────────────────────────

/// Wire-status + code mapping for [`RegistrationError`]. Mirrors the
/// `AuthError::status()` + `AuthError::code()` pattern so the §4.7.9
/// envelope stays uniform across all locksmith error sources.
fn registration_status_code(err: &RegistrationError) -> (StatusCode, &'static str, &'static str) {
    match err {
        RegistrationError::DefinitionPending => {
            (StatusCode::CONFLICT, "conflict", "definition_pending")
        }
        RegistrationError::InvalidMcp => (StatusCode::BAD_REQUEST, "bad_request", "invalid_mcp"),
        RegistrationError::InvalidHttpService => (
            StatusCode::BAD_REQUEST,
            "bad_request",
            "invalid_http_service",
        ),
        RegistrationError::InvalidUpstream => {
            (StatusCode::BAD_REQUEST, "bad_request", "invalid_upstream")
        }
        RegistrationError::NameInUse { .. } => (StatusCode::CONFLICT, "conflict", "name_in_use"),
        RegistrationError::WrongKind { .. } => (StatusCode::CONFLICT, "conflict", "wrong_kind"),
        RegistrationError::ReservedName => {
            (StatusCode::BAD_REQUEST, "bad_request", "reserved_name")
        }
        RegistrationError::InvalidName(_) => {
            (StatusCode::BAD_REQUEST, "bad_request", "invalid_name")
        }
        RegistrationError::AuthRequired => {
            (StatusCode::BAD_REQUEST, "bad_request", "auth_required")
        }
        RegistrationError::ModelAuthRequired => (
            StatusCode::BAD_REQUEST,
            "bad_request",
            "model_auth_required",
        ),
        RegistrationError::InvalidMetadata(_) => {
            (StatusCode::BAD_REQUEST, "bad_request", "invalid_metadata")
        }
        RegistrationError::Backend(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "auth_error",
            "internal_error",
        ),
    }
}

/// Render a `RegistrationError` through the §4.7.9 envelope. Wire message
/// is `err.to_string()` — matches the AuthError convention. Backend
/// errors render the generic "internal error" string thanks to the
/// `#[error("internal error")]` annotation on that variant.
pub fn registration_error_response(err: &RegistrationError) -> Response {
    let (status, type_, code) = registration_status_code(err);
    let body = json!({
        "error": {
            "message": err.to_string(),
            "type": type_,
            "code": code,
        }
    });
    (status, Json(body)).into_response()
}

/// 404 envelope for unknown names (admin GET / DELETE / enable on a name
/// that doesn't exist). Not modeled in `RegistrationError` because the
/// repo's `get` returns `Option<Registration>` — caller surfaces the
/// 404 explicitly.
pub fn unknown_name_response(name: &str) -> Response {
    let body = json!({
        "error": {
            "message": format!("registration not found: {name}"),
            "type": "not_found",
            "code": "unknown_name",
        }
    });
    (StatusCode::NOT_FOUND, Json(body)).into_response()
}

// ─── Admin handlers (HTTP-shaped) ──────────────────────────────────────────

/// State carried by the admin registrations handlers. The thin shape lets
/// `src/admin/uds.rs` derive its own state struct without depending on
/// the full `AppState`.
///
/// Phase E.6 — `catalog` and `resolved_creds` are optional refs into the
/// agent router's `AppState`. When wired (production daemon), admin
/// writes refresh both after a successful upsert/delete/enable so the
/// proxy hot path sees the new state without a daemon restart. When
/// `None` (older tests or pre-Phase-E paths), admin writes still hit
/// the repo but no in-memory cache exists to invalidate.
#[derive(Clone)]
pub struct AdminRegistrationsState {
    pub local_listener: Option<(String, u16)>,
    pub repo: Arc<RegistrationRepository>,
    pub catalog: Option<Arc<arc_swap::ArcSwap<crate::registrations::Catalog>>>,
    pub resolved_creds: Option<Arc<arc_swap::ArcSwap<crate::secret::ResolvedCreds>>>,
    /// Phase J (ADR-0008) — credential-store sealing key. `None` when
    /// `LOCKSMITH_CREDENTIAL_SEALING_KEY` is unset; the set-value / clear
    /// credential routes then behave as if absent (404) — the sealing-key
    /// gate. `Some` seals operator-supplied values before storage (CCS-1).
    pub credential_sealing_key: Option<crate::secret::CredentialSealingKey>,
    /// Phase J (ADR-0008) — sealed `credential_secrets` store. `Some`
    /// only when `credential_sealing_key` is present, so "no key" cleanly
    /// means "feature off".
    pub credential_secrets: Option<crate::repo::CredentialSecretsRepository>,
    /// Phase J / M2 (LOG-2, registry emit site) — operational-log emitter.
    /// `None` outside the production daemon. Records registration
    /// create/update/delete on the `registry` component (secret-free).
    pub operational_log: Option<Arc<crate::operational_log_sink::OperationalLogEmitter>>,
    /// Phase J / M2 (CCS-8, T2.2) — `op://` resolver cache shared with the
    /// proxy hot path. [`refresh_runtime`](Self::refresh_runtime) resyncs
    /// it so an `op_*` registration added or changed at runtime resolves
    /// without a restart. `None` outside the production daemon.
    pub op_resolver: Option<Arc<crate::secret::OpResolver>>,
    /// Per-agent override repo — read by the `op` resync so references
    /// used only by an override stay resolved.
    pub agent_creds: Option<crate::repo::AgentCredentialRepository>,
}

impl AdminRegistrationsState {
    /// Emit a `registry` operational-log event (create/update/delete of a
    /// registration). No-op when the emitter isn't wired. Secret-free —
    /// records only the registration name + kind + action (LOG-4).
    fn emit_registry(&self, action: &str, kind: Kind, name: &str) {
        if let Some(emitter) = self.operational_log.as_ref() {
            emitter.emit(
                crate::repo::LogLevel::Info,
                crate::repo::LogComponent::Registry,
                format!("registration_{action}"),
                format!("registration {action}: {kind} {name}"),
                Some(json!({ "kind": kind.to_string(), "name": name, "action": action })),
            );
        }
    }

    /// Phase E.6 — refresh the in-memory catalog from the repo and
    /// extend `resolved_creds` with any new env-var references. Called
    /// after every successful admin write so the proxy hot path sees
    /// the new state immediately. A failed refresh reports persisted-but-failed
    /// activation. Admission independently denies any changed stale row.
    pub async fn refresh_runtime(
        &self,
    ) -> Result<(), crate::registrations::admission::AdmissionUnavailable> {
        let Some(catalog) = self.catalog.as_ref() else {
            return Ok(()); // Admin-only configuration surface; reads report pending.
        };
        let new_catalog = match crate::registrations::Catalog::from_repo(self.repo.as_ref()).await {
            Ok(c) => c,
            Err(e) => {
                let _ = e; // Raw parse errors can contain stored source input.
                tracing::error!(
                    "catalog refresh failed; saved configuration is pending activation"
                );
                return Err(crate::registrations::admission::AdmissionUnavailable);
            }
        };

        if let Some(creds_swap) = self.resolved_creds.as_ref() {
            let extra = crate::secret::resolve_registration_creds_sync_env_only(&new_catalog);
            if !extra.is_empty() {
                let snap = creds_swap.load();
                let mut merged = (**snap).clone();
                for (k, v) in extra {
                    // Operator may have changed the env_var or pointed
                    // at a different env var; overwrite instead of
                    // entry-or-insert.
                    merged.insert(k, v);
                }
                creds_swap.store(Arc::new(merged));
            }
        }

        catalog.store(Arc::new(new_catalog));

        if let Some(resolver) = self.op_resolver.as_ref() {
            crate::secret::resync_op_references(resolver, catalog, self.agent_creds.as_ref()).await;
        }
        Ok(())
    }

    pub(crate) fn describe(&self, registration: &Registration) -> Value {
        let mut value = registration_to_admin_json(registration);
        let catalog = self.catalog.as_ref().map(|c| c.load());
        value["configured"] = true.into();
        if registration.definition_pinned() {
            value["authoring_only"] = true.into();
            value["provider_readiness"] = "unverified".into();
        }
        value["activation"] = crate::registrations::admission::activation(
            registration,
            catalog.as_deref().map(|c| c.as_ref()),
        )
        .into();
        value["credential_readiness"] = "not_checked".into();
        value
    }
}

fn activation_failed() -> Response {
    (StatusCode::SERVICE_UNAVAILABLE, Json(json!({
        "saved": true, "activation": "failed", "credential_readiness": "not_checked",
        "error": {"type":"availability_error", "code":"connection_activation_failed",
            "message":"configuration saved; runtime activation failed. Inspect the registration, repair invalid catalog data, then repeat the intended write or restart the deployment. Current authority remains enforced."}
    }))).into_response()
}

/// `GET /admin/operator/<kind>` — list all of `kind`. Always includes
/// `disabled=true` rows (operator-facing — they want to see what's
/// suppressed).
pub async fn op_list(State(state): State<AdminRegistrationsState>, kind: Kind) -> Response {
    match state.repo.list(Some(kind)).await {
        Ok(rows) => {
            let items: Vec<Value> = rows.iter().map(|r| state.describe(r)).collect();
            (StatusCode::OK, Json(json!({ format!("{kind}s"): items }))).into_response()
        }
        Err(e) => registration_error_response(&e),
    }
}

/// `GET /admin/operator/<kind>/<name>`.
pub async fn op_get(
    State(state): State<AdminRegistrationsState>,
    kind: Kind,
    name: String,
) -> Response {
    match state.repo.get(&name).await {
        Ok(Some(r)) => {
            if r.kind != kind {
                return registration_error_response(&RegistrationError::WrongKind {
                    existing_kind: r.kind,
                    requested_kind: kind,
                });
            }
            (StatusCode::OK, Json(state.describe(&r))).into_response()
        }
        Ok(None) => unknown_name_response(&name),
        Err(e) => registration_error_response(&e),
    }
}

/// `PUT /admin/operator/<kind>/<name>` — upsert. On insert: validates
/// name (charset, length, reserved) and per-kind auth requirements
/// (tool/model need explicit auth, including none). On existing
/// row: enforces kind immutability (URL kind must match existing). Sets
/// `seed=false` (operator-owned). Preserves `disabled` flag — operator
/// uses DELETE (or set_disabled) to flip it.
pub async fn op_put(
    State(state): State<AdminRegistrationsState>,
    kind: Kind,
    name: String,
    body: PutBody,
) -> Response {
    // Name validation runs first — most likely cheap rejection point.
    if let Err(e) = validate_name(&name) {
        return registration_error_response(&e);
    }
    if let Err(e) = super::protocol::validate(
        body.protocol,
        body.mcp.as_ref(),
        kind,
        body.egress.unwrap_or_default(),
        &body.upstream,
        body.metadata.as_ref(),
    ) {
        return registration_error_response(&e);
    }
    if let Some(metadata) = &body.metadata
        && let Err(e) = super::http_service::from_metadata(metadata)
    {
        return registration_error_response(&e);
    }

    if body.protocol == super::Protocol::McpStreamableHttp
        && state
            .local_listener
            .as_ref()
            .is_some_and(|(host, port)| super::protocol::is_self(&body.upstream, host, *port))
    {
        return registration_error_response(&RegistrationError::InvalidMcp);
    }

    if body.mcp.as_ref().is_some_and(|m| m.definition.is_some()) {
        return registration_error_response(&RegistrationError::DefinitionPending);
    }

    // Kind-aware auth resolution.
    //
    // - kind=tool requires the field to be present (use `auth: none` for
    //   authless; field absent → `auth_required`).
    // - kind=model requires the field to be present (field absent →
    //   `auth_required`). `auth: none` IS accepted on kind=model — for
    //   self-hosted/LAN-local inference (Ollama, LM Studio) where the
    //   upstream doesn't require auth. Operators who want to require
    //   auth on a model just don't specify `none`.
    // - kind=infra accepts any shape including field-absent (becomes
    //   `AuthSpec::None`).
    let auth = match (kind, body.auth) {
        (Kind::Tool, None) | (Kind::Model, None) => {
            return registration_error_response(&RegistrationError::AuthRequired);
        }
        (Kind::Infra, None) => AuthSpec::None,
        (_, Some(a)) => a,
    };

    // Phase J / M2 (CCS-2): an `op` custody reference must use the `op://`
    // scheme. Reject a malformed reference at register-time so it never
    // reaches the resolver (which would otherwise silently degrade it).
    if matches!(auth, AuthSpec::ControlledOauth { .. }) {
        return registration_error_response(&RegistrationError::InvalidMetadata(
            "selection_only".into(),
        ));
    }
    if let Err(msg) = auth.validate_op_reference() {
        return registration_error_response(&RegistrationError::InvalidMetadata(msg));
    }

    // Existing row? Check kind immutability + preserve created_at + disabled.
    let now = unix_now();
    let (created_at, disabled) = match state.repo.get(&name).await {
        Ok(Some(existing)) => {
            if existing.definition_pinned() {
                return registration_error_response(&RegistrationError::DefinitionPending);
            }
            if existing.kind != kind {
                return registration_error_response(&RegistrationError::WrongKind {
                    existing_kind: existing.kind,
                    requested_kind: kind,
                });
            }
            (existing.created_at, existing.disabled)
        }
        Ok(None) => (now, false),
        Err(e) => return registration_error_response(&e),
    };

    let r = Registration {
        name: name.clone(),
        protocol: body.protocol,
        mcp: body.mcp,
        kind,
        description: body.description,
        upstream: body.upstream,
        auth,
        egress: body.egress.unwrap_or_default(),
        timeouts: body.timeouts.unwrap_or_default(),
        body_limit_bytes: body.body_limit_bytes.unwrap_or(10 * 1024 * 1024),
        metadata: body
            .metadata
            .unwrap_or_else(|| Value::Object(serde_json::Map::new())),
        seed: false, // PUT always flips to operator-owned
        disabled,
        created_at,
        updated_at: now,
    };

    let is_update = created_at != now;
    if let Err(e) = state.repo.upsert(&r).await {
        return registration_error_response(&e);
    }
    if state.refresh_runtime().await.is_err() {
        return activation_failed();
    }
    state.emit_registry(if is_update { "updated" } else { "created" }, kind, &name);

    (StatusCode::OK, Json(state.describe(&r))).into_response()
}

/// `DELETE /admin/operator/<kind>/<name>`. For seed rows: sets `disabled=1`
/// (sticky across image upgrades). For operator-registered rows: hard delete.
pub async fn op_delete(
    State(state): State<AdminRegistrationsState>,
    kind: Kind,
    name: String,
) -> Response {
    match state.repo.get(&name).await {
        Ok(Some(r)) => {
            if r.kind != kind {
                return registration_error_response(&RegistrationError::WrongKind {
                    existing_kind: r.kind,
                    requested_kind: kind,
                });
            }
            let result = if r.seed {
                state.repo.set_disabled(&name, true).await
            } else {
                state.repo.delete(&name).await.map(|_| true)
            };
            match result {
                Ok(_) => {
                    if state.refresh_runtime().await.is_err() {
                        return activation_failed();
                    }
                    state.emit_registry("deleted", kind, &name);
                    StatusCode::NO_CONTENT.into_response()
                }
                Err(e) => registration_error_response(&e),
            }
        }
        Ok(None) => unknown_name_response(&name),
        Err(e) => registration_error_response(&e),
    }
}

/// `POST /admin/operator/<kind>/<name>/enable` — un-disable a previously-
/// disabled row. No-op if the row is already enabled.
pub async fn op_enable(
    State(state): State<AdminRegistrationsState>,
    kind: Kind,
    name: String,
) -> Response {
    match state.repo.get(&name).await {
        Ok(Some(r)) => {
            if r.definition_pinned() {
                return registration_error_response(&RegistrationError::DefinitionPending);
            }
            if r.kind != kind {
                return registration_error_response(&RegistrationError::WrongKind {
                    existing_kind: r.kind,
                    requested_kind: kind,
                });
            }
            match state.repo.set_disabled(&name, false).await {
                Ok(_) => {
                    if state.refresh_runtime().await.is_err() {
                        return activation_failed();
                    }
                    StatusCode::NO_CONTENT.into_response()
                }
                Err(e) => registration_error_response(&e),
            }
        }
        Ok(None) => unknown_name_response(&name),
        Err(e) => registration_error_response(&e),
    }
}

// ─── Phase J (ADR-0008) — stored-credential set-value + clear ──────────────
//
// `PUT /admin/operator/<kind>/<name>/credential` seals an operator-supplied
// value into the `credential_secrets` store and rewrites the registration's
// AuthSpec to a `stored_*` variant carrying only the opaque `secret_ref`
// (CCS-3 / CCS-6). `DELETE` clears it back to `AuthSpec::None`. Both are
// gated on the credential sealing key: when the daemon booted without
// `LOCKSMITH_CREDENTIAL_SEALING_KEY`, the routes 404 (feature off), mirroring
// the OAuth-key gate.

/// `PUT /admin/operator/<kind>/<name>/credential` — seal + store a value.
///
/// Fetches the registration (404 on absent / kind mismatch); when the
/// sealing key + store aren't configured, 404s (the feature gate). Seals
/// the value, then rechecks the registration and atomically inserts custody
/// plus the auth attachment. A refusal rolls back both. Preserves the current
/// header name if the registration
/// already injects a `Header`/`StoredHeader` (→ `StoredHeader`), else
/// `StoredBearer`. Tombstones the prior stored ref on rotation. Returns a
/// shape-only `{secret_ref, set_at}` — the value is NEVER echoed (CCS-1).
pub async fn op_put_credential(
    State(state): State<AdminRegistrationsState>,
    kind: Kind,
    name: String,
    body: PutCredentialBody,
) -> Response {
    // Sealing-key gate: feature off ⇒ 404 (route behaves as if absent).
    let (Some(key), Some(secrets)) = (
        state.credential_sealing_key.as_ref(),
        state.credential_secrets.as_ref(),
    ) else {
        return unknown_name_response(&name);
    };

    let existing = match state.repo.get(&name).await {
        Ok(Some(r)) => r,
        Ok(None) => return unknown_name_response(&name),
        Err(e) => return registration_error_response(&e),
    };
    if existing.definition_pinned() {
        return registration_error_response(&RegistrationError::DefinitionPending);
    }
    if existing.kind != kind {
        return registration_error_response(&RegistrationError::WrongKind {
            existing_kind: existing.kind,
            requested_kind: kind,
        });
    }

    // Seal the cleartext; the SecretString zeroizes on drop. Never logged /
    // echoed (CCS-1).
    let (sealed, nonce) = match key.seal(body.value.expose_secret().as_bytes()) {
        Ok(pair) => pair,
        Err(e) => {
            return registration_error_response(&RegistrationError::Backend(format!(
                "credential seal failed: {e}"
            )));
        }
    };
    let old_ref = existing.auth.stored_secret_ref().map(str::to_owned);
    let now = unix_now();
    let secret_ref = match state
        .repo
        .store_credential(&existing, &sealed, &nonce)
        .await
    {
        Ok(reference) => reference,
        Err(e) => return registration_error_response(&e),
    };

    // Tombstone the rotated ref only after the upsert succeeds, so a
    // failed write never orphans the live secret.
    if let Some(old) = old_ref
        && let Err(e) = secrets.tombstone_if_unreferenced(&old).await
    {
        tracing::warn!(error = %e, "tombstone of rotated credential ref failed");
    }

    if state.refresh_runtime().await.is_err() {
        return activation_failed();
    }

    (
        StatusCode::OK,
        Json(json!({ "secret_ref": secret_ref, "set_at": now })),
    )
        .into_response()
}

/// `DELETE /admin/operator/<kind>/<name>/credential` — clear a stored
/// credential. Tombstones the current `stored_*` secret (if any) and resets
/// the registration's auth to `AuthSpec::None`. Idempotent: returns 200 even
/// when nothing was stored. Gated on the sealing key (404 when unconfigured).
pub async fn op_delete_credential(
    State(state): State<AdminRegistrationsState>,
    kind: Kind,
    name: String,
) -> Response {
    let (Some(_key), Some(secrets)) = (
        state.credential_sealing_key.as_ref(),
        state.credential_secrets.as_ref(),
    ) else {
        return unknown_name_response(&name);
    };

    let existing = match state.repo.get(&name).await {
        Ok(Some(r)) => r,
        Ok(None) => return unknown_name_response(&name),
        Err(e) => return registration_error_response(&e),
    };
    if existing.definition_pinned() {
        return registration_error_response(&RegistrationError::DefinitionPending);
    }
    if existing.kind != kind {
        return registration_error_response(&RegistrationError::WrongKind {
            existing_kind: existing.kind,
            requested_kind: kind,
        });
    }

    if let Some(old) = existing.auth.stored_secret_ref().map(|s| s.to_string()) {
        let now = unix_now();
        let updated = Registration {
            auth: AuthSpec::None,
            seed: false,
            updated_at: now,
            ..existing
        };
        if let Err(e) = state.repo.upsert(&updated).await {
            return registration_error_response(&e);
        }
        if let Err(e) = secrets.tombstone_if_unreferenced(&old).await {
            tracing::warn!(error = %e, "tombstone of cleared credential ref failed");
        }
        if state.refresh_runtime().await.is_err() {
            return activation_failed();
        }
    }

    (StatusCode::OK, Json(json!({ "cleared": true }))).into_response()
}

// ─── Per-kind shim handlers (axum-routable) ────────────────────────────────
//
// axum's `Path` extractor needs a concrete type at compile time. Rather than
// route everything through `/admin/operator/{kind}/{name}` and pay an
// enum-parse cost on every request, we mount three independent path
// segments (`tools`, `models`, `infra`) and register per-kind shims that
// call into the kind-agnostic core handlers above.

use axum::extract::Path;

pub async fn op_list_tools(state: State<AdminRegistrationsState>) -> Response {
    op_list(state, Kind::Tool).await
}

pub async fn op_list_models(state: State<AdminRegistrationsState>) -> Response {
    op_list(state, Kind::Model).await
}

pub async fn op_list_infra(state: State<AdminRegistrationsState>) -> Response {
    op_list(state, Kind::Infra).await
}

pub async fn op_get_tool(
    state: State<AdminRegistrationsState>,
    Path(name): Path<String>,
) -> Response {
    op_get(state, Kind::Tool, name).await
}

pub async fn op_get_model(
    state: State<AdminRegistrationsState>,
    Path(name): Path<String>,
) -> Response {
    op_get(state, Kind::Model, name).await
}

pub async fn op_get_infra(
    state: State<AdminRegistrationsState>,
    Path(name): Path<String>,
) -> Response {
    op_get(state, Kind::Infra, name).await
}

pub async fn op_put_tool(
    state: State<AdminRegistrationsState>,
    Path(name): Path<String>,
    Json(body): Json<PutBody>,
) -> Response {
    op_put(state, Kind::Tool, name, body).await
}

pub async fn op_put_model(
    state: State<AdminRegistrationsState>,
    Path(name): Path<String>,
    Json(body): Json<PutBody>,
) -> Response {
    op_put(state, Kind::Model, name, body).await
}

pub async fn op_put_infra(
    state: State<AdminRegistrationsState>,
    Path(name): Path<String>,
    Json(body): Json<PutBody>,
) -> Response {
    op_put(state, Kind::Infra, name, body).await
}

pub async fn op_delete_tool(
    state: State<AdminRegistrationsState>,
    Path(name): Path<String>,
) -> Response {
    op_delete(state, Kind::Tool, name).await
}

pub async fn op_delete_model(
    state: State<AdminRegistrationsState>,
    Path(name): Path<String>,
) -> Response {
    op_delete(state, Kind::Model, name).await
}

pub async fn op_delete_infra(
    state: State<AdminRegistrationsState>,
    Path(name): Path<String>,
) -> Response {
    op_delete(state, Kind::Infra, name).await
}

pub async fn op_enable_tool(
    state: State<AdminRegistrationsState>,
    Path(name): Path<String>,
) -> Response {
    op_enable(state, Kind::Tool, name).await
}

pub async fn op_enable_model(
    state: State<AdminRegistrationsState>,
    Path(name): Path<String>,
) -> Response {
    op_enable(state, Kind::Model, name).await
}

pub async fn op_enable_infra(
    state: State<AdminRegistrationsState>,
    Path(name): Path<String>,
) -> Response {
    op_enable(state, Kind::Infra, name).await
}

// Phase J (ADR-0008) — per-kind credential set-value / clear shims.

pub async fn op_put_tool_credential(
    state: State<AdminRegistrationsState>,
    Path(name): Path<String>,
    Json(body): Json<PutCredentialBody>,
) -> Response {
    op_put_credential(state, Kind::Tool, name, body).await
}

pub async fn op_put_model_credential(
    state: State<AdminRegistrationsState>,
    Path(name): Path<String>,
    Json(body): Json<PutCredentialBody>,
) -> Response {
    op_put_credential(state, Kind::Model, name, body).await
}

pub async fn op_put_infra_credential(
    state: State<AdminRegistrationsState>,
    Path(name): Path<String>,
    Json(body): Json<PutCredentialBody>,
) -> Response {
    op_put_credential(state, Kind::Infra, name, body).await
}

pub async fn op_delete_tool_credential(
    state: State<AdminRegistrationsState>,
    Path(name): Path<String>,
) -> Response {
    op_delete_credential(state, Kind::Tool, name).await
}

pub async fn op_delete_model_credential(
    state: State<AdminRegistrationsState>,
    Path(name): Path<String>,
) -> Response {
    op_delete_credential(state, Kind::Model, name).await
}

pub async fn op_delete_infra_credential(
    state: State<AdminRegistrationsState>,
    Path(name): Path<String>,
) -> Response {
    op_delete_credential(state, Kind::Infra, name).await
}

// ─── Helpers ────────────────────────────────────────────────────────────────

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
