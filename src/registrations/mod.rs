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

pub mod admission;
pub mod api;
pub mod auth_spec;
pub mod backends;
pub mod backends_api;
pub mod broker;
pub mod catalog;
mod credential;
mod definitions;
pub mod http_service;
pub mod kind;
pub mod legacy_bootstrap;
pub mod profile;
pub mod protocol;
pub mod repo;
pub mod seed_loader;
pub mod upstream_ca;
pub mod validators;

pub use auth_spec::AuthSpec;
pub use catalog::Catalog;
pub use kind::Kind;
pub use profile::RouteProfile;
pub use protocol::{McpConfig, Protocol};
pub use repo::{Registration, RegistrationRepository};
pub use validators::{MAX_NAME_LEN, RESERVED_NAMES, validate_name, validate_upstream};

/// Registration-layer errors. Wire-rendering happens in `api.rs` (E.3).
#[derive(Debug, Clone, thiserror::Error)]
pub enum RegistrationError {
    #[error("definition-derived connection is disabled pending provider and promotion contracts")]
    DefinitionPending,

    #[error("invalid native MCP configuration; use the documented HTTPS tool profile")]
    InvalidMcp,

    #[error(
        "invalid http_service: use the version 1 request_response JSON contract with relative operation paths"
    )]
    InvalidHttpService,

    /// Invalid HTTP base URL. Never echo input that may contain credentials.
    #[error(
        "invalid upstream: use an absolute HTTP(S) base URL without userinfo, query or fragment"
    )]
    InvalidUpstream,

    /// Per-route CA (#135) unusable: not 1..=16 X.509 PEM certificates
    /// (64 KiB max), or set on a non-HTTPS or native MCP route.
    /// Wire: 400 bad_request / `invalid_upstream_ca`.
    #[error(
        "invalid upstream_ca_pem: use 1-16 PEM certificates on an HTTPS upstream of an HTTP route"
    )]
    InvalidUpstreamCa,

    /// Route profile not one of the known wire values (brokered routes
    /// phase 1). Wire: 400 bad_request / `invalid_profile`.
    #[error("invalid profile: use generic or openai-codex-responses")]
    InvalidProfile,

    /// Broker spec unusable (brokered routes phase 3): bad header name,
    /// health probe or key kind, or `broker` used as a template.
    /// Wire: 400 bad_request / `invalid_broker`.
    #[error("invalid broker: {0}")]
    InvalidBroker(String),

    /// A route PUT that would turn an upstream route into a broker or
    /// back. Wire: 409 conflict / `broker_kind_change`.
    #[error("broker kind change: use a new route or a backend switch")]
    BrokerKindChange,

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
