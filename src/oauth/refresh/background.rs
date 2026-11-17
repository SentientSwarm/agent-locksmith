use super::*;

struct Task {
    repo: OauthSessionRepository,
    catalog: Arc<arc_swap::ArcSwap<Catalog>>,
    bindings: crate::repo::AgentCredentialRepository,
    key: SealingKey,
    locks: RefreshLockMap,
    log: Option<Arc<crate::operational_log_sink::OperationalLogEmitter>>,
    clients: crate::client_pool::OauthClients,
    skipped: Skipped,
}

/// AGENT-302: sessions whose refresh was skipped for want of egress, so
/// the skip is reported once rather than on every tick, until a refresh
/// of that session gets a client again. Bounded by the sessions.
#[derive(Default)]
struct Skipped(std::sync::Mutex<std::collections::HashSet<(String, String)>>);

impl Skipped {
    /// True the first time in a row that `(name, label)` is skipped.
    fn first(&self, name: &str, label: &str) -> bool {
        self.0.lock().map_or(true, |mut s| {
            s.insert((name.to_string(), label.to_string()))
        })
    }

    fn clear(&self, name: &str, label: &str) {
        if let Ok(mut s) = self.0.lock() {
            s.remove(&(name.to_string(), label.to_string()));
        }
    }
}

/// Refresh selected accounts under the same per-label lock as proxy/bootstrap.
#[allow(clippy::too_many_arguments)]
pub async fn run(
    repo: OauthSessionRepository,
    catalog: Arc<arc_swap::ArcSwap<Catalog>>,
    bindings: crate::repo::AgentCredentialRepository,
    key: SealingKey,
    locks: RefreshLockMap,
    clients: crate::client_pool::OauthClients,
    operational_log: Option<Arc<crate::operational_log_sink::OperationalLogEmitter>>,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) {
    let task = Task {
        repo,
        catalog,
        bindings,
        key,
        locks,
        log: operational_log,
        clients,
        skipped: Skipped::default(),
    };
    task.run(shutdown).await;
}

impl Task {
    async fn run(self, shutdown: impl std::future::Future<Output = ()>) {
        let mut ticker = tokio::time::interval(Duration::from_secs(REFRESH_TICK_SECS));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        tokio::select! {
            biased;
            _ = shutdown => info!("oauth refresh task stopped"),
            _ = async { loop { ticker.tick().await; self.tick().await; } } => {},
        }
    }

    async fn tick(&self) {
        let threshold = unix_now() + DEFAULT_REFRESH_SAFETY_MARGIN_SECS;
        let items = match self.repo.list_pending_refresh(threshold).await {
            Ok(items) => items,
            Err(_) => {
                warn!("oauth refresh: list_pending_refresh failed");
                return;
            }
        };
        for (name, label) in items {
            self.locks
                .owner
                .run(self.refresh(&name, &label, threshold))
                .await;
        }
    }

    async fn refresh(&self, name: &str, label: &str, threshold: i64) {
        let Some(egress) = self.catalog.load().lookup_active(name).map(|r| r.egress) else {
            return;
        };
        // AGENT-269: the token call takes the route's egress. With none
        // usable the route is unusable too, so the session is left as is.
        let client = match self.clients.for_egress(egress) {
            Ok(client) => {
                self.skipped.clear(name, label);
                client
            }
            Err(cause) => {
                if self.skipped.first(name, label) {
                    self.report_skip(name, label, cause.describe().0);
                }
                return;
            }
        };
        let lock = self.locks.get(name, label).await;
        let _guard = lock.lock().await;
        let Some(selection) = self.selection(name, label).await else {
            return;
        };
        let Some(session) = self.current(name, label, threshold).await else {
            return;
        };
        if let Err(e) =
            refresh_selected_session(&self.repo, &selection, &self.key, client, &session).await
        {
            record_failure(&self.repo, &session, &e, self.log.as_deref()).await;
        }
    }

    /// The token call has no egress, so the session can't be refreshed and
    /// will expire: say so once, in the daemon log and the operational log.
    fn report_skip(&self, name: &str, label: &str, cause: &str) {
        warn!(
            name,
            session_label = label,
            cause,
            "oauth refresh skipped: no egress for the token call"
        );
        if let Some(log) = &self.log {
            log.emit(
                crate::repo::LogLevel::Warn,
                crate::repo::LogComponent::Oauth,
                "oauth_refresh_skipped",
                "OAuth refresh skipped: the route's token call has no egress",
                Some(serde_json::json!({ "registration": name, "session_label": label, "cause": cause })),
            );
        }
    }

    async fn selection(&self, name: &str, label: &str) -> Option<AuthSpec> {
        match selected_source(&self.bindings, name, label).await {
            Ok(selection) => selection,
            Err(_) => {
                warn!(
                    name,
                    session_label = label,
                    "OAuth selection unavailable or conflicting; refresh skipped"
                );
                None
            }
        }
    }

    async fn current(&self, name: &str, label: &str, threshold: i64) -> Option<OauthSession> {
        // Re-read inside the lock: another caller may already have refreshed.
        match self.repo.get(&self.key, name, label).await {
            Ok(Some(s))
                if !s.degraded
                    && !s.refresh_pending
                    && s.access_token_expires_at.is_none_or(|e| e <= threshold) =>
            {
                Some(s)
            }
            Ok(_) => None,
            Err(_) => {
                warn!(
                    name,
                    session_label = label,
                    "oauth refresh: get failed; skipping"
                );
                None
            }
        }
    }
}

#[cfg(test)]
mod skipped_tests {
    use super::Skipped;

    /// AGENT-302: a session skipped for want of egress is logged once,
    /// not on every tick, and again only after a refresh got a client.
    #[test]
    fn a_skip_is_reported_once_until_egress_returns() {
        let s = Skipped::default();
        assert!(s.first("r", "a"));
        assert!(!s.first("r", "a"));
        assert!(s.first("r", "b"), "another label is its own session");
        s.clear("r", "a");
        assert!(s.first("r", "a"));
    }
}
