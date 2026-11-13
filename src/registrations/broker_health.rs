//! Brokered routes phase 3 — broker health.
//!
//! [`Prober`] periodically sends `GET <upstream><health.path>` with the
//! route's broker key to every enabled broker route that declares a health
//! probe, and records the result in [`BrokerHealth`]. Admission refuses a
//! route whose last probe failed (503 `backend_unavailable`, no dispatch);
//! a route never probed is admitted. A down broker never fails daemon
//! readiness, because other routes still serve.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use arc_swap::ArcSwap;
use secrecy::{ExposeSecret, SecretString};
use serde_json::json;

use super::{AuthSpec, Catalog, Kind, Registration};
use crate::client_pool::ClientPool;
use crate::config::AppConfig;
use crate::operational_log_sink::OperationalLogEmitter;
use crate::repo::{CredentialSecretsRepository, LogComponent, LogLevel};
use crate::secret::{CredentialSealingKey, OpResolver};

/// How long one probe may take before the broker counts as down.
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(5);
/// How often the prober wakes to look for due probes.
pub const TICK: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum HealthStatus {
    Up,
    Down,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct HealthState {
    pub status: HealthStatus,
    pub checked_at: i64,
    pub http_status: Option<u16>,
    /// [`fingerprint`] of the destination probed. A result for any other
    /// destination, key or probe counts as unknown.
    #[serde(skip)]
    pub fingerprint: String,
}

/// Identifies what a probe tested: upstream, egress, CA, key and probe.
/// `None` when the registration declares no probe.
pub fn fingerprint(r: &Registration) -> Option<String> {
    use sha2::Digest;
    let probe = r.broker.as_ref()?.health.as_ref()?;
    let doc = json!([r.upstream, r.egress, r.upstream_ca_pem, r.auth, probe]);
    Some(format!("{:x}", sha2::Sha256::digest(doc.to_string())))
}

/// Last probe result per broker route, shared by the prober, admission
/// and `/readyz`.
#[derive(Clone, Default)]
pub struct BrokerHealth(Arc<RwLock<HashMap<String, HealthState>>>);

/// Broker health counts for `/readyz` (no route names).
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Counts {
    pub up: usize,
    pub down: usize,
    pub unknown: usize,
}

impl BrokerHealth {
    pub fn get(&self, route: &str) -> Option<HealthState> {
        self.0.read().ok()?.get(route).cloned()
    }

    /// Record a probe result and return the previous status, if any.
    pub fn set(&self, route: &str, state: HealthState) -> Option<HealthStatus> {
        let mut map = self.0.write().ok()?;
        map.insert(route.to_string(), state).map(|prev| prev.status)
    }

    /// The last result for `r`'s current destination; `None` when `r`
    /// declares no probe or was not probed as it is now.
    pub fn current(&self, r: &Registration) -> Option<HealthState> {
        let fp = fingerprint(r)?;
        self.get(&r.name).filter(|s| s.fingerprint == fp)
    }

    /// Forget every route not in `keep`.
    fn retain(&self, keep: &std::collections::HashSet<&str>) {
        if let Ok(mut map) = self.0.write() {
            map.retain(|name, _| keep.contains(name.as_str()));
        }
    }

    /// Counts over the catalog's probed brokers.
    pub fn counts(&self, catalog: &Catalog) -> Counts {
        let mut c = Counts::default();
        for r in probed(catalog) {
            match self.current(r).map(|s| s.status) {
                Some(HealthStatus::Up) => c.up += 1,
                Some(HealthStatus::Down) => c.down += 1,
                None => c.unknown += 1,
            }
        }
        c
    }
}

/// Enabled HTTP broker routes that declare a health probe.
fn probed(catalog: &Catalog) -> impl Iterator<Item = &Arc<Registration>> {
    [Kind::Tool, Kind::Model]
        .into_iter()
        .flat_map(|k| catalog.iter_enabled_by_kind(k))
        .filter(|r| r.broker.as_ref().is_some_and(|b| b.health.is_some()))
}

pub struct Prober {
    health: BrokerHealth,
    catalog: Arc<ArcSwap<Catalog>>,
    config: Arc<ArcSwap<AppConfig>>,
    sealing_key: Option<CredentialSealingKey>,
    secrets: Option<CredentialSecretsRepository>,
    op_resolver: Option<Arc<OpResolver>>,
    oplog: Option<Arc<OperationalLogEmitter>>,
    clients: ClientPool,
}

impl Prober {
    pub fn new(
        health: BrokerHealth,
        catalog: Arc<ArcSwap<Catalog>>,
        config: Arc<ArcSwap<AppConfig>>,
        sealing_key: Option<CredentialSealingKey>,
        secrets: Option<CredentialSecretsRepository>,
        op_resolver: Option<Arc<OpResolver>>,
        oplog: Option<Arc<OperationalLogEmitter>>,
    ) -> Self {
        Self {
            health,
            catalog,
            config,
            sealing_key,
            secrets,
            op_resolver,
            oplog,
            clients: ClientPool::new(),
        }
    }

    /// Probe, concurrently, every broker whose interval has elapsed by
    /// `now` (unix seconds), and record the results.
    pub async fn tick_at(&self, now: i64) {
        let catalog = self.catalog.load_full();
        self.health
            .retain(&probed(&catalog).map(|r| r.name.as_str()).collect());
        // A result for an earlier destination makes the route due now.
        let due: Vec<_> = probed(&catalog)
            .filter(|r| {
                let every = r.broker.as_ref().and_then(|b| b.health.as_ref());
                let every = every.map_or(30, |h| h.interval_seconds) as i64;
                self.health
                    .current(r)
                    .is_none_or(|s| now.saturating_sub(s.checked_at) >= every)
            })
            .cloned()
            .collect();
        let results =
            futures_util::future::join_all(due.iter().map(|r| self.probe_once(r, now))).await;
        for (r, state) in due.iter().zip(results) {
            let (status, http_status) = (state.status, state.http_status);
            let prev = self.health.current(r).map(|s| s.status);
            self.health.set(&r.name, state);
            // Log changes, and a first probe that fails; a first success
            // is the expected state and stays quiet.
            if prev != Some(status) && !(prev.is_none() && status == HealthStatus::Up) {
                self.log_transition(&r.name, status, http_status);
            }
        }
    }

    /// Probe one broker route.
    pub async fn probe_once(&self, r: &Registration, now: i64) -> HealthState {
        let fp = fingerprint(r).unwrap_or_default();
        let down = |http_status| HealthState {
            status: HealthStatus::Down,
            checked_at: now,
            http_status,
            fingerprint: fp.clone(),
        };
        let Some(probe) = r.broker.as_ref().and_then(|b| b.health.as_ref()) else {
            return down(None);
        };
        let Some(key) = self.key(&r.auth).await else {
            return down(None);
        };
        let config = self.config.load();
        let client = self.clients.get_or_build_for(
            &r.name,
            r.timeouts,
            r.egress,
            r.upstream_ca_pem.as_deref(),
            &config,
        );
        let url = format!("{}{}", r.upstream.trim_end_matches('/'), probe.path);
        let req = match r.auth.header_name() {
            Some(h) => client.get(url).header(h, key.expose_secret()),
            None => client.get(url).bearer_auth(key.expose_secret()),
        };
        match req.timeout(PROBE_TIMEOUT).send().await {
            Ok(resp) => {
                let code = resp.status().as_u16();
                HealthState {
                    status: if code == probe.expect_status {
                        HealthStatus::Up
                    } else {
                        HealthStatus::Down
                    },
                    checked_at: now,
                    http_status: Some(code),
                    fingerprint: fp,
                }
            }
            Err(_) => down(None),
        }
    }

    /// Run until `shutdown` resolves, ticking every [`TICK`].
    pub async fn run(self, shutdown: impl std::future::Future<Output = ()> + Send + 'static) {
        let mut ticker = tokio::time::interval(TICK);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        tokio::pin!(shutdown);
        loop {
            tokio::select! {
                _ = &mut shutdown => return,
                _ = ticker.tick() => self.tick_at(super::backends::unix_now()).await,
            }
        }
    }

    /// The broker key's value, or `None` when it cannot be materialized.
    async fn key(&self, auth: &AuthSpec) -> Option<SecretString> {
        match auth {
            AuthSpec::StoredBearer { secret_ref } | AuthSpec::StoredHeader { secret_ref, .. } => {
                let (key, secrets) = (self.sealing_key.as_ref()?, self.secrets.as_ref()?);
                let sealed = secrets.get(secret_ref).await.ok()??;
                let plain = key.unseal(&sealed.sealed_value, &sealed.nonce).ok()?;
                String::from_utf8(plain).ok().map(SecretString::from)
            }
            AuthSpec::OpBearer { reference } | AuthSpec::OpHeader { reference, .. } => {
                self.op_resolver.as_ref()?.get(reference)
            }
            _ => None,
        }
    }

    fn log_transition(&self, route: &str, status: HealthStatus, http_status: Option<u16>) {
        let Some(oplog) = &self.oplog else { return };
        let (level, event, message) = match status {
            HealthStatus::Down => (
                LogLevel::Warn,
                "broker_down",
                "broker failed its health probe",
            ),
            HealthStatus::Up => (
                LogLevel::Info,
                "broker_up",
                "broker passed its health probe",
            ),
        };
        oplog.emit(
            level,
            LogComponent::Broker,
            event,
            message,
            Some(json!({ "route": route, "http_status": http_status })),
        );
    }
}
