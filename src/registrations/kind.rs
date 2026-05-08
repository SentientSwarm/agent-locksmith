//! Kind discriminator for registrations: model | tool | infra.
//!
//! Locked at devloop `phase-e-catalog-substrate` Design phase. See
//! `agents-stack/docs/spec/v0.2.0.md` (forthcoming) for the formal spec.

use serde::{Deserialize, Serialize};

/// Kind of a locksmith registration. Three values, no extension.
///
/// - `Model` — LLM, embedding, reranker, audio, image — anything model-shaped.
///   Discoverable via `GET /models` (ACL-filtered). Requires non-`None` auth.
/// - `Tool` — anything that's not a model. Web search, code repos, document fetch,
///   sandboxes. Discoverable via `GET /tools` (ACL-filtered). May be authless.
/// - `Infra` — operator-only middleware the proxy itself calls. NOT agent-discoverable.
///   Today: `lf-scan`. Future: scanners, validators.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Model,
    Tool,
    Infra,
}

impl Kind {
    /// Plural URL segment used in admin endpoint paths (`/admin/<segment>/<name>`).
    /// Note `Infra` stays singular because no canonical plural feels right and
    /// it's operator-only — agents never see these URLs anyway.
    pub fn url_segment(&self) -> &'static str {
        match self {
            Kind::Model => "models",
            Kind::Tool => "tools",
            Kind::Infra => "infra",
        }
    }

    /// Display name for human-facing CLI / log output.
    pub fn as_str(&self) -> &'static str {
        match self {
            Kind::Model => "model",
            Kind::Tool => "tool",
            Kind::Infra => "infra",
        }
    }
}

impl std::fmt::Display for Kind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}
