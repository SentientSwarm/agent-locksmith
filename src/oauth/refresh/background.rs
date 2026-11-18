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

/// A skip that goes on is reported again this often, so the operational
/// log, which keeps rows for `operational_log.retention_days`, always holds
/// a recent one while the session goes unrefreshed (AGENT-302).
const SKIP_REPORT_EVERY: Duration = Duration::from_secs(24 * 60 * 60);

/// AGENT-302: sessions whose refresh was skipped for want of egress, with
/// when each skip was last reported, so it is reported once rather than
/// on every tick, then daily, until a refresh of that session gets a
/// client again. Bounded by the sessions.
#[derive(Default)]
struct Skipped(std::sync::Mutex<std::collections::HashMap<(String, String), std::time::Instant>>);

impl Skipped {
    /// True when `(name, label)`'s skip should be reported at `now`: the
    /// first time in a row, or `SKIP_REPORT_EVERY` after the last report.
    fn due(&self, name: &str, label: &str, now: std::time::Instant) -> bool {
        self.0.lock().map_or(true, |mut s| {
            let key = (name.to_string(), label.to_string());
            let reported = s
                .get(&key)
                .is_some_and(|last| now.saturating_duration_since(*last) < SKIP_REPORT_EVERY);
            if !reported {
                s.insert(key, now);
            }
            !reported
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
                if self.skipped.due(name, label, std::time::Instant::now()) {
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
    /// will expire: say so, in the daemon log and the operational log.
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
    use super::{SKIP_REPORT_EVERY, Skipped};
    use std::time::{Duration, Instant};

    /// AGENT-302: a session skipped for want of egress is logged once, not
    /// on every tick; again a day later while the skip lasts, so the
    /// operational log keeps a current row; and again at once after a
    /// refresh got a client.
    #[test]
    fn a_skip_is_reported_once_a_day_until_egress_returns() {
        let s = Skipped::default();
        let t0 = Instant::now();
        assert!(s.due("r", "a", t0));
        assert!(!s.due("r", "a", t0 + Duration::from_secs(30)));
        assert!(s.due("r", "b", t0), "another label is its own session");
        let day = t0 + SKIP_REPORT_EVERY;
        assert!(!s.due("r", "a", day - Duration::from_secs(1)));
        assert!(s.due("r", "a", day));
        assert!(!s.due("r", "a", day + Duration::from_secs(30)));
        s.clear("r", "a");
        assert!(s.due("r", "a", day + Duration::from_secs(60)));
    }
}

#[cfg(test)]
mod wiring_tests {
    use super::*;
    use crate::migrations::open_and_migrate;
    use crate::operational_log_sink::OperationalLogEmitter;
    use crate::registrations::{Kind, Registration, RegistrationRepository};
    use crate::repo::{LogFilter, OperationalLogStore};

    /// AGENT-302: `refresh` reports a proxied route's skip through
    /// `Skipped`: two ticks with no egress write one operational-log row.
    #[tokio::test]
    async fn two_skipped_ticks_write_one_log_row() {
        let dir = tempfile::TempDir::new().unwrap();
        let pool = open_and_migrate(&dir.path().join("db.sqlite"))
            .await
            .unwrap();
        let registrations = RegistrationRepository::new(pool.clone());
        let mut r = Registration::new(
            "codex".into(),
            Kind::Model,
            "proxied OAuth route".into(),
            "https://api.example.com".into(),
            AuthSpec::OauthDeviceCode {
                client_id: "c".into(),
                scopes: vec![],
                device_url: "https://auth.example.com/device".into(),
                token_url: "https://auth.example.com/token".into(),
                session_label: None,
            },
        );
        r.egress = crate::config::EgressMode::Proxied;
        registrations.create(&r).await.unwrap();
        let catalog = Catalog::from_repo(&registrations).await.unwrap();
        let store = OperationalLogStore::new(pool.clone());
        let config = crate::config::parse_config_str(
            "listen:\n  host: \"127.0.0.1\"\n  port: 9200\ntools: []\n",
        )
        .unwrap();
        let task = Task {
            repo: OauthSessionRepository::new(pool.clone()),
            catalog: Arc::new(arc_swap::ArcSwap::from_pointee(catalog)),
            bindings: crate::repo::AgentCredentialRepository::new(pool),
            key: SealingKey::generate().unwrap(),
            locks: RefreshLockMap::new(),
            log: Some(Arc::new(OperationalLogEmitter::spawn(store.clone(), 16))),
            clients: crate::client_pool::OauthClients::new(&config),
            skipped: Skipped::default(),
        };
        task.refresh("codex", "default", unix_now()).await;
        task.refresh("codex", "default", unix_now()).await;
        let filter = LogFilter {
            limit: 10,
            ..LogFilter::default()
        };
        for _ in 0..100 {
            if !store.query(&filter).await.unwrap().is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        // Give a second row, if one were written, time to land.
        tokio::time::sleep(Duration::from_millis(100)).await;
        let rows = store.query(&filter).await.unwrap();
        assert_eq!(rows.len(), 1, "{rows:?}");
        assert_eq!(rows[0].event, "oauth_refresh_skipped");
        let fields = rows[0].fields.clone().unwrap();
        assert_eq!(fields["registration"], "codex");
        assert_eq!(fields["session_label"], "default");
    }
}
