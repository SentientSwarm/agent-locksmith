//! OAuth session token cache + refresh logic (Phase F.3).
//!
//! Implements ADR-0005:
//! - **D2** — AES-GCM sealing of refresh + access tokens, sealing key
//!   from `LOCKSMITH_OAUTH_SEALING_KEY` env var (32 bytes random).
//! - **D3** — refresh-ahead-of-expiry: `min(5 minutes, lifetime / 4)`
//!   with a 60s floor.
//! - **D4** — audit field shape (`auth_mode: oauth_pkce | oauth_device_code`,
//!   `oauth_session_id` derived from `name + created_at`).
//! - **D6** — failure semantics: refresh failure marks `degraded=1`, no
//!   auto-retry, operator action required.
//!
//! Module layout:
//! - [`sealing`] — sealing key bootstrap + AES-GCM encrypt/decrypt.
//! - [`session`] — `OauthSession` record + `OauthSessionRepository` for
//!   CRUD on the `oauth_sessions` table.
//! - [`refresh`] — background refresh task + per-session mutex for
//!   concurrent-refresh safety.
//!
//! The first-time auth bootstrap CLI (Phase F.4) and proxy hot-path
//! dispatch (Phase F.5) consume the types defined here.

pub mod admin;
pub mod refresh;
pub mod sealing;
pub mod session;

pub use admin::OauthAdminState;
pub use sealing::{SealingKey, SealingKeyError};
pub use session::{OauthSession, OauthSessionError, OauthSessionRepository};
