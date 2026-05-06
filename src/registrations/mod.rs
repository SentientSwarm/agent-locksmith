//! Phase E (v2.0.0): kind-discriminated registrations.
//!
//! Replaces the pre-Phase-E `config.tools: Vec<ToolConfig>` with a
//! database-backed catalog of `Registration` rows discriminated by
//! [`Kind`] (model / tool / infra). Seed catalog populates first-boot;
//! operator overrides via admin API.
//!
//! Module layout:
//! - [`kind`]        — the [`Kind`] enum.
//! - [`auth_spec`]   — the [`AuthSpec`] enum (`None` / `Header` / `Bearer`).
//! - [`validators`]  — `validate_name()` + `RESERVED_NAMES`.
//!
//! Forthcoming in later subtasks (E.2..E.7):
//! - `repo`          — sqlx persistence layer.
//! - `api`           — admin HTTP handlers.
//! - `seed_loader`   — first-boot loader for `/etc/locksmith/seed/catalog.yaml`.

pub mod api;
pub mod auth_spec;
pub mod kind;
pub mod repo;
pub mod seed_loader;
pub mod validators;

pub use auth_spec::AuthSpec;
pub use kind::Kind;
pub use repo::{Registration, RegistrationRepository};
pub use validators::{MAX_NAME_LEN, RESERVED_NAMES, validate_name};

/// Registration-layer errors. Wire-rendering happens in `api.rs` (E.3).
#[derive(Debug, Clone, thiserror::Error)]
pub enum RegistrationError {
    /// Cross-kind name reuse — `name` is already registered under a
    /// different kind. Wire: 409 conflict / `name_in_use`.
    #[error("name in use (existing kind: {existing_kind})")]
    NameInUse { existing_kind: Kind },

    /// `name` is on the reserved list. Wire: 400 bad_request / `reserved_name`.
    #[error("name is reserved")]
    ReservedName,

    /// `kind=tool` registered without an explicit `auth:` block. The
    /// implicit-absence-means-none footgun is closed at v2.0.0; operators
    /// must state intent. Wire: 400 bad_request / `auth_required`.
    #[error("kind=tool requires explicit `auth:` (use `auth: none` for authless)")]
    AuthRequired,

    /// `kind=model` registered with `auth: none`. No v2.0.0 model
    /// upstream is authless. Wire: 400 bad_request / `model_auth_required`.
    #[error("kind=model requires non-none auth")]
    ModelAuthRequired,

    /// Name fails charset / length / format validation. Wire: 400
    /// bad_request / `invalid_name`. The static string carries the
    /// specific reason for diagnostic surfaces; the wire message stays
    /// generic per Q-8 / §4.7.9.
    #[error("invalid name: {0}")]
    InvalidName(&'static str),

    /// Per-kind metadata violation (missing required field, invalid enum
    /// value). Wire: 400 bad_request / `invalid_metadata`.
    #[error("invalid metadata: {0}")]
    InvalidMetadata(String),

    /// URL kind doesn't match existing row's kind (e.g., `PUT /admin/models/foo`
    /// when `foo` was registered as `kind=tool`). Wire: 409 conflict / `wrong_kind`.
    #[error("wrong kind (registered as {existing_kind}, requested {requested_kind})")]
    WrongKind {
        existing_kind: Kind,
        requested_kind: Kind,
    },

    /// Backend persistence failure (DB unreachable, etc.). Wire message is
    /// scrubbed (`internal error`) per AuthError::Backend convention from
    /// M9 / verify-iter-3; inner cause preserved for tracing only.
    #[error("internal error")]
    Backend(String),
}
