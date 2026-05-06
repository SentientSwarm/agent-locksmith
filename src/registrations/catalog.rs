//! Phase E.6 — in-memory `Catalog` cache.
//!
//! Mirrors the `registrations` table for read-only hot-path access.
//! Built at daemon start (after seed_loader + legacy_bootstrap) and
//! refreshed after each admin write that changes the table. The proxy
//! hot path looks up by name; `/tools` and `/models` discovery
//! handlers can use the kind-filtered iterator instead of round-
//! tripping the DB on every request.
//!
//! Stores `Arc<Registration>` so handlers can pass references through
//! futures without cloning the row body. The `Catalog` itself is
//! wrapped in `ArcSwap` at the AppState level for lock-free reads
//! plus atomic refresh.

use crate::registrations::{Kind, Registration, RegistrationError, RegistrationRepository};
use std::collections::HashMap;
use std::sync::Arc;

/// Read-only snapshot of the registrations table. See module docs.
#[derive(Debug, Default)]
pub struct Catalog {
    by_name: HashMap<String, Arc<Registration>>,
}

impl Catalog {
    /// Build a fresh `Catalog` from the repository. Reads every row
    /// (across all kinds, including `disabled=true`); callers filter as
    /// needed.
    pub async fn from_repo(repo: &RegistrationRepository) -> Result<Self, RegistrationError> {
        let rows = repo.list(None).await?;
        let mut by_name = HashMap::with_capacity(rows.len());
        for r in rows {
            by_name.insert(r.name.clone(), Arc::new(r));
        }
        Ok(Self { by_name })
    }

    /// Look up a registration by name. Returns `None` for unknown names
    /// and for `disabled=true` rows (the proxy hot path treats both as
    /// not-found; admin operations that need to see disabled rows go
    /// through the repo directly).
    pub fn lookup_active(&self, name: &str) -> Option<&Arc<Registration>> {
        self.by_name.get(name).filter(|r| !r.disabled)
    }

    /// Look up a registration by name, including disabled rows.
    pub fn lookup_any(&self, name: &str) -> Option<&Arc<Registration>> {
        self.by_name.get(name)
    }

    /// Iterate over enabled registrations of a given kind. Used by the
    /// `/tools` and `/models` discovery handlers as a hot-path
    /// alternative to round-tripping the DB.
    pub fn iter_enabled_by_kind(&self, kind: Kind) -> impl Iterator<Item = &Arc<Registration>> {
        self.by_name
            .values()
            .filter(move |r| r.kind == kind && !r.disabled)
    }

    pub fn len(&self) -> usize {
        self.by_name.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_name.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registrations::{AuthSpec, Kind, Registration};

    fn r(name: &str, kind: Kind, disabled: bool) -> Registration {
        let mut r = Registration::new(
            name.to_string(),
            kind,
            String::new(),
            "https://example.com".to_string(),
            AuthSpec::None,
        );
        r.disabled = disabled;
        r
    }

    fn catalog(rows: Vec<Registration>) -> Catalog {
        let by_name = rows
            .into_iter()
            .map(|r| (r.name.clone(), Arc::new(r)))
            .collect();
        Catalog { by_name }
    }

    #[test]
    fn lookup_active_skips_disabled() {
        let c = catalog(vec![
            r("foo", Kind::Tool, false),
            r("bar", Kind::Tool, true),
        ]);
        assert!(c.lookup_active("foo").is_some());
        assert!(c.lookup_active("bar").is_none());
        assert!(c.lookup_any("bar").is_some());
    }

    #[test]
    fn iter_enabled_by_kind_filters() {
        let c = catalog(vec![
            r("a", Kind::Tool, false),
            r("b", Kind::Model, false),
            r("c", Kind::Tool, true),
            r("d", Kind::Infra, false),
        ]);
        let tools: Vec<_> = c
            .iter_enabled_by_kind(Kind::Tool)
            .map(|r| r.name.clone())
            .collect();
        assert_eq!(tools, vec!["a"]);
        let models: Vec<_> = c
            .iter_enabled_by_kind(Kind::Model)
            .map(|r| r.name.clone())
            .collect();
        assert_eq!(models, vec!["b"]);
    }
}
