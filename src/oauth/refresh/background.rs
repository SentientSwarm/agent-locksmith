use super::*;

struct Task {
    repo: OauthSessionRepository,
    catalog: Arc<arc_swap::ArcSwap<Catalog>>,
    bindings: crate::repo::AgentCredentialRepository,
    key: SealingKey,
    locks: RefreshLockMap,
    log: Option<Arc<crate::operational_log_sink::OperationalLogEmitter>>,
    client: reqwest::Client,
}

/// Refresh selected accounts under the same per-label lock as proxy/bootstrap.
#[allow(clippy::too_many_arguments)]
pub async fn run(
    repo: OauthSessionRepository,
    catalog: Arc<arc_swap::ArcSwap<Catalog>>,
    bindings: crate::repo::AgentCredentialRepository,
    key: SealingKey,
    locks: RefreshLockMap,
    operational_log: Option<Arc<crate::operational_log_sink::OperationalLogEmitter>>,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());
    let task = Task {
        repo,
        catalog,
        bindings,
        key,
        locks,
        log: operational_log,
        client,
    };
    task.run(shutdown).await;
}

impl Task {
    async fn run(self, shutdown: impl std::future::Future<Output = ()>) {
        let mut ticker = tokio::time::interval(Duration::from_secs(REFRESH_TICK_SECS));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        tokio::pin!(shutdown);
        loop {
            tokio::select! {
                _ = &mut shutdown => {
                    info!("oauth refresh task: shutdown signal observed; exiting");
                    return;
                }
                _ = ticker.tick() => self.tick().await,
            }
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
            self.refresh(&name, &label, threshold).await;
        }
    }

    async fn refresh(&self, name: &str, label: &str, threshold: i64) {
        if self.catalog.load().lookup_active(name).is_none() {
            return;
        }
        let lock = self.locks.get(name, label).await;
        let _guard = lock.lock().await;
        let Some(selection) = self.selection(name, label).await else {
            return;
        };
        let Some(session) = self.current(name, label, threshold).await else {
            return;
        };
        if let Err(e) =
            refresh_selected_session(&self.repo, &selection, &self.key, &self.client, &session)
                .await
        {
            record_failure(&self.repo, &session, &e, self.log.as_deref()).await;
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
                if !s.degraded && s.access_token_expires_at.is_none_or(|e| e <= threshold) =>
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
