//! Brokered routes phase 3 — broker health.
//!
//! [`Prober`] periodically sends `GET <upstream><health.path>` with the
//! route's broker key to every enabled broker route that declares a health
//! probe, and records the result in [`BrokerHealth`]. Admission refuses a
//! route whose last probe failed (503 `backend_unavailable`, no dispatch);
//! a route never probed is admitted. A broker that fails a probe it could
//! reach (an unexpected status, a timeout or a refused connection) is
//! probed again [`RETRY_AFTER`] seconds later and counts as down only
//! after [`DOWN_AFTER`] such failures in a row (AGENT-310, AGENT-312).
//! Until then its last recorded result stands. A down broker never
//! fails daemon readiness, because other routes still serve.

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
use crate::secret::materialize::{self, KeyFailure};
use crate::secret::{CredentialSealingKey, OpResolver};

/// How long one probe may take before the broker counts as down.
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(5);
/// How often the prober wakes to look for due probes.
pub const TICK: Duration = Duration::from_secs(5);
/// Failed probes in a row, each retried [`RETRY_AFTER`] seconds after the
/// last, before a broker counts as down. Three absorb about 20 s of
/// slowness, nearly all of the 21 s AGENT-310 incident (AGENT-314). A refusal
/// that no retry changes (no usable egress client) counts at once.
pub const DOWN_AFTER: u32 = 3;
/// Seconds from a failed probe's start to its retry: the probe timeout and
/// a tick (AGENT-312). Without the tick, a probe that timed out would be
/// retried the moment it ended, into the same slow spell.
pub const RETRY_AFTER: i64 = (PROBE_TIMEOUT.as_secs() + TICK.as_secs()) as i64;

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
    /// Why a probe failed (AGENT-269): `unexpected_status`, `unreachable`
    /// (any transport error: connect, TLS, timeout or a refusal by the
    /// egress proxy), or the refusal code when no client may
    /// reach the broker (`egress_proxy_unconfigured`,
    /// `upstream_client_unavailable`). `None` when up.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cause: Option<&'static str>,
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

    /// Forget `route`'s last result, so it counts as unknown.
    fn forget(&self, route: &str) {
        if let Ok(mut map) = self.0.write() {
            map.remove(route);
        }
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

struct Strike {
    fingerprint: String,
    count: u32,
    at: i64,
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
    /// Routes whose key could not be materialized at their last probe.
    key_unresolved: std::sync::Mutex<std::collections::HashSet<String>>,
    /// Failed probes in a row not yet recorded, by route: the fingerprint
    /// they were made against, how many, and when the last started.
    strikes: std::sync::Mutex<HashMap<String, Strike>>,
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
            key_unresolved: Default::default(),
            strikes: Default::default(),
        }
    }

    /// Probe, concurrently, every broker whose interval has elapsed by
    /// `now` (unix seconds), and record the results.
    pub async fn tick_at(&self, now: i64) {
        let catalog = self.catalog.load_full();
        let keep: std::collections::HashSet<&str> =
            probed(&catalog).map(|r| r.name.as_str()).collect();
        self.health.retain(&keep);
        if let Ok(mut set) = self.key_unresolved.lock() {
            set.retain(|name| keep.contains(name.as_str()));
        }
        if let Ok(mut strikes) = self.strikes.lock() {
            strikes.retain(|name, _| keep.contains(name.as_str()));
        }
        // A result for an earlier destination makes the route due now. A
        // failure still to be confirmed is due only at its retry, however
        // old the last recorded result.
        let due: Vec<_> = probed(&catalog)
            .filter(|r| {
                let every = r.broker.as_ref().and_then(|b| b.health.as_ref());
                let every = every.map_or(30, |h| h.interval_seconds) as i64;
                self.retry_due(r, now).unwrap_or_else(|| {
                    self.health
                        .current(r)
                        .is_none_or(|s| now.saturating_sub(s.checked_at) >= every)
                })
            })
            .cloned()
            .collect();
        let results =
            futures_util::future::join_all(due.iter().map(|r| self.probe_once(r, now))).await;
        for (r, result) in due.iter().zip(results) {
            let state = match result {
                Ok(state) => {
                    self.key_resolved(&r.name);
                    state
                }
                Err(failure) => {
                    self.key_failed(&r.name, failure);
                    continue;
                }
            };
            let (status, http_status, cause) = (state.status, state.http_status, state.cause);
            let prev = self.health.current(r).map(|s| s.status);
            if self.strike(&r.name, &state, prev) {
                continue;
            }
            self.health.set(&r.name, state);
            // Log changes, and a first probe that fails; a first success
            // is the expected state and stays quiet.
            if prev != Some(status) && !(prev.is_none() && status == HealthStatus::Up) {
                self.log_transition(&r.name, status, http_status, cause);
            }
        }
    }

    /// Whether a failed probe of `r`, against its current destination, is
    /// due its retry at `now`; `None` when no retry is pending.
    fn retry_due(&self, r: &Registration, now: i64) -> Option<bool> {
        let fp = fingerprint(r).unwrap_or_default();
        let strikes = self.strikes.lock().ok()?;
        let k = strikes.get(&r.name).filter(|k| k.fingerprint == fp)?;
        Some(now.saturating_sub(k.at) >= RETRY_AFTER)
    }

    /// Count a probe a retry might pass (the broker answered wrongly or
    /// not at all) while the route is not down; true while the failures in
    /// a row are fewer than [`DOWN_AFTER`], so the result is not recorded
    /// yet. Any recorded result clears the count.
    fn strike(&self, route: &str, state: &HealthState, prev: Option<HealthStatus>) -> bool {
        let Ok(mut strikes) = self.strikes.lock() else {
            return false;
        };
        let retryable = matches!(state.cause, Some("unexpected_status" | "unreachable"));
        if state.status != HealthStatus::Down || !retryable || prev == Some(HealthStatus::Down) {
            strikes.remove(route);
            return false;
        }
        let entry = strikes.entry(route.to_string()).or_insert(Strike {
            fingerprint: state.fingerprint.clone(),
            count: 0,
            at: state.checked_at,
        });
        if entry.fingerprint != state.fingerprint {
            entry.fingerprint = state.fingerprint.clone();
            entry.count = 0;
        }
        entry.count += 1;
        entry.at = state.checked_at;
        if entry.count < DOWN_AFTER {
            tracing::info!(
                route,
                cause = state.cause,
                http_status = state.http_status,
                failures = entry.count,
                "broker health probe failed; retrying before marking it down"
            );
            return true;
        }
        strikes.remove(route);
        false
    }

    /// Probe one broker route. A key that cannot be materialized is not a
    /// broker failure: it is reported as such and the route is not probed
    /// (#159), so admission reports the key, not the broker.
    async fn probe_once(&self, r: &Registration, now: i64) -> Result<HealthState, KeyFailure> {
        let fp = fingerprint(r).unwrap_or_default();
        let down = |http_status, cause| HealthState {
            status: HealthStatus::Down,
            checked_at: now,
            http_status,
            cause: Some(cause),
            fingerprint: fp.clone(),
        };
        // Unreachable: `probed` keeps only brokers with a health probe. Kept
        // so a future caller gets a down state, not a panic.
        let Some(probe) = r.broker.as_ref().and_then(|b| b.health.as_ref()) else {
            return Ok(down(None, "no_probe"));
        };
        let key = self.key(&r.auth).await?;
        let config = self.config.load();
        let client = self.clients.get_or_build_for(
            &r.name,
            r.timeouts,
            r.egress,
            r.upstream_ca_pem.as_deref(),
            &config,
        );
        // AGENT-259 — a proxied broker with no enforced egress is down,
        // not probed directly.
        let client = match client {
            Ok(client) => client,
            Err(refused) => return Ok(down(None, refused.describe().1)),
        };
        let url = format!("{}{}", r.upstream.trim_end_matches('/'), probe.path);
        let req = match r.auth.header_name() {
            Some(h) => client.get(url).header(h, key.expose_secret()),
            None => client.get(url).bearer_auth(key.expose_secret()),
        };
        Ok(match req.timeout(PROBE_TIMEOUT).send().await {
            Ok(resp) => {
                let code = resp.status().as_u16();
                if code == probe.expect_status {
                    HealthState {
                        status: HealthStatus::Up,
                        checked_at: now,
                        http_status: Some(code),
                        cause: None,
                        fingerprint: fp.clone(),
                    }
                } else {
                    down(Some(code), "unexpected_status")
                }
            }
            Err(_) => down(None, "unreachable"),
        })
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

    /// The broker key's value, materialized exactly as the proxy does.
    async fn key(&self, auth: &AuthSpec) -> Result<SecretString, KeyFailure> {
        match auth {
            AuthSpec::StoredBearer { secret_ref } | AuthSpec::StoredHeader { secret_ref, .. } => {
                materialize::stored(self.sealing_key.as_ref(), self.secrets.as_ref(), secret_ref)
                    .await
            }
            AuthSpec::OpBearer { reference } | AuthSpec::OpHeader { reference, .. } => {
                materialize::op(self.op_resolver.as_deref(), reference)
            }
            _ => Err(KeyFailure::Missing),
        }
    }

    /// Forget the route's health and log, once, that its key is unusable.
    fn key_failed(&self, route: &str, failure: KeyFailure) {
        self.health.forget(route);
        // The broker was not probed: its earlier failure is no longer the
        // last thing known of it (AGENT-312).
        if let Ok(mut strikes) = self.strikes.lock() {
            strikes.remove(route);
        }
        let first = self
            .key_unresolved
            .lock()
            .map(|mut set| set.insert(route.to_string()))
            .unwrap_or(false);
        if let (true, Some(oplog)) = (first, &self.oplog) {
            oplog.emit(
                LogLevel::Warn,
                LogComponent::Broker,
                "broker_key_unresolved",
                "broker key could not be materialized; health probe skipped",
                Some(json!({ "route": route, "cause": failure.cause() })),
            );
        }
    }

    fn key_resolved(&self, route: &str) {
        if let Ok(mut set) = self.key_unresolved.lock() {
            set.remove(route);
        }
    }

    fn log_transition(
        &self,
        route: &str,
        status: HealthStatus,
        http_status: Option<u16>,
        cause: Option<&'static str>,
    ) {
        // Also in the daemon's own log (AGENT-310): operators read the
        // container log before the operational-log API.
        match status {
            HealthStatus::Down => {
                tracing::warn!(route, http_status, cause, "broker failed its health probe")
            }
            HealthStatus::Up => tracing::info!(route, "broker passed its health probe"),
        }
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
            Some(json!({ "route": route, "http_status": http_status, "cause": cause })),
        );
    }
}
