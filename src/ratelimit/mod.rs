//! AGENT-266 — per-agent, per-route rate limits.
//!
//! Limits live in the `rate_limits` table (migration 0027) and are
//! mirrored here so the proxy checks them without a query. A route
//! default applies to every agent separately; an agent row overrides it.
//! Each (agent, route) gets a token bucket of `requests_per_minute`
//! tokens, refilled continuously, and, with `max_concurrent`, a cap on
//! an in-flight count the request holds until its body is dropped.

pub mod repo;

use arc_swap::ArcSwap;
use serde::Serialize;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub use repo::{RateLimitRepository, RateLimitRow};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Limit {
    pub requests_per_minute: u32,
    pub max_concurrent: Option<u32>,
}

/// A slot's refusals of each kind (rate, concurrency) write at most one
/// audit row per this interval (AGENT-272), so an agent hammering a
/// limited route cannot turn each refusal into an audit write.
pub const AUDIT_EVERY: Duration = Duration::from_secs(60);

/// Why a request was refused, and when a retry can succeed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limited {
    pub retry_after_secs: u64,
    pub concurrency: bool,
    /// `Some(n)`: write an audit row for this refusal, which also stands
    /// for the `n` refusals of its kind on the slot since that kind's
    /// previous row. `None`: counted toward the next row instead.
    pub audit: Option<u64>,
}

/// Limits by route, then by agent id (`None` is the route default).
type Table = HashMap<String, HashMap<Option<i64>, Limit>>;

#[derive(Default)]
pub struct RateLimiter {
    limits: ArcSwap<Table>,
    slots: Mutex<HashMap<(i64, String), Slot>>,
}

struct Slot {
    limit: Limit,
    tokens: f64,
    at: Instant,
    /// Requests admitted and not yet finished. One counter for the slot's
    /// life, so a changed cap still counts what is already in flight
    /// (AGENT-272); it counts even while the route has no cap.
    inflight: Arc<AtomicUsize>,
    /// For rate (`[0]`) and concurrency (`[1]`) refusals apart: when one
    /// last wrote an audit row, and refusals since (AGENT-272).
    audited_at: [Option<Instant>; 2],
    unaudited: [u64; 2],
}

/// One admitted request, held until its response body is dropped.
#[derive(Debug)]
pub struct Permit(Arc<AtomicUsize>);

impl Drop for Permit {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

impl Slot {
    fn new(limit: Limit, now: Instant) -> Self {
        Self {
            limit,
            tokens: f64::from(limit.requests_per_minute),
            at: now,
            inflight: Arc::new(AtomicUsize::new(0)),
            audited_at: [None; 2],
            unaudited: [0; 2],
        }
    }

    fn refuse(&mut self, now: Instant, retry_after_secs: u64, concurrency: bool) -> Limited {
        let reason = usize::from(concurrency);
        let audit = match self.audited_at[reason] {
            Some(at) if now.saturating_duration_since(at) < AUDIT_EVERY => {
                self.unaudited[reason] += 1;
                None
            }
            _ => {
                self.audited_at[reason] = Some(now);
                Some(std::mem::take(&mut self.unaudited[reason]))
            }
        };
        Limited {
            retry_after_secs,
            concurrency,
            audit,
        }
    }

    /// A changed rate starts a fresh bucket. A changed concurrency cap
    /// applies to the same in-flight count. Either starts new audit
    /// windows, so the first refusal under it is recorded, counting the
    /// ones held back before (AGENT-272).
    fn adopt(&mut self, limit: Limit, now: Instant) {
        if self.limit != limit {
            self.audited_at = [None; 2];
        }
        if self.limit.requests_per_minute != limit.requests_per_minute {
            self.tokens = f64::from(limit.requests_per_minute);
            self.at = now;
        }
        self.limit = limit;
    }
}

impl RateLimiter {
    /// Replace every limit. Buckets for routes that lost their limit go.
    pub fn replace(&self, rows: impl IntoIterator<Item = (String, Option<i64>, Limit)>) {
        let mut table = Table::new();
        for (route, agent, limit) in rows {
            table.entry(route).or_default().insert(agent, limit);
        }
        self.lock()
            .retain(|(_, route), _| table.contains_key(route));
        self.limits.store(Arc::new(table));
    }

    /// Admit one request from `agent` on `route`. `Ok(Some(permit))`
    /// counts it as in flight until the permit is dropped.
    pub fn check(&self, agent: i64, route: &str) -> Result<Option<Permit>, Limited> {
        self.check_at(agent, route, Instant::now())
    }

    fn check_at(&self, agent: i64, route: &str, now: Instant) -> Result<Option<Permit>, Limited> {
        let limits = self.limits.load();
        let Some(by_agent) = limits.get(route) else {
            return Ok(None);
        };
        let Some(&limit) = by_agent.get(&Some(agent)).or_else(|| by_agent.get(&None)) else {
            return Ok(None);
        };
        let mut slots = self.lock();
        let slot = slots
            .entry((agent, route.to_string()))
            .or_insert_with(|| Slot::new(limit, now));
        slot.adopt(limit, now);
        // Under the slots lock nothing else admits on this slot, and the
        // count only falls meanwhile, so check-then-add cannot over-admit.
        if let Some(cap) = limit.max_concurrent
            && slot.inflight.load(Ordering::Acquire) >= cap as usize
        {
            return Err(slot.refuse(now, 1, true));
        }
        slot.inflight.fetch_add(1, Ordering::AcqRel);
        // Dropped on a rate refusal below, which undoes the count.
        let permit = Some(Permit(slot.inflight.clone()));
        let rate = f64::from(limit.requests_per_minute) / 60.0;
        let elapsed = now.saturating_duration_since(slot.at).as_secs_f64();
        slot.tokens = (slot.tokens + elapsed * rate).min(f64::from(limit.requests_per_minute));
        slot.at = now;
        if slot.tokens < 1.0 {
            // The epsilon keeps float error from adding a second.
            let wait = ((1.0 - slot.tokens) / rate - 1e-9).ceil() as u64;
            return Err(slot.refuse(now, wait.max(1), false));
        }
        slot.tokens -= 1.0;
        Ok(permit)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<(i64, String), Slot>> {
        self.slots.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// The repository and the limiter it feeds, shared by the admin API.
pub struct RateLimits {
    pub repo: RateLimitRepository,
    pub limiter: Arc<RateLimiter>,
    /// AGENT-272 — one reload at a time, so a slower reload cannot
    /// publish a table older than one already published.
    reload_lock: tokio::sync::Mutex<()>,
}

impl RateLimits {
    pub fn new(repo: RateLimitRepository, limiter: Arc<RateLimiter>) -> Self {
        Self {
            repo,
            limiter,
            reload_lock: tokio::sync::Mutex::new(()),
        }
    }

    /// Load every row into the limiter.
    pub async fn reload(&self) -> Result<(), sqlx::Error> {
        let _one_at_a_time = self.reload_lock.lock().await;
        let rows = self.repo.list().await?;
        self.limiter
            .replace(rows.into_iter().map(|r| (r.route, r.agent_id, r.limit)));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn cap(n: u32) -> Limit {
        Limit {
            requests_per_minute: 1000,
            max_concurrent: Some(n),
        }
    }

    /// AGENT-272: changing the cap keeps counting requests already in
    /// flight, so raising it admits only the difference and lowering it
    /// admits nothing until enough finish.
    #[test]
    fn a_cap_change_keeps_counting_requests_in_flight() {
        let l = RateLimiter::default();
        let t0 = Instant::now();
        l.replace([("r".to_string(), None, cap(2))]);
        let held: Vec<_> = (0..2).map(|_| l.check_at(1, "r", t0).unwrap()).collect();
        assert!(l.check_at(1, "r", t0).is_err());

        l.replace([("r".to_string(), None, cap(3))]);
        let third = l.check_at(1, "r", t0).unwrap();
        assert!(
            l.check_at(1, "r", t0).is_err(),
            "raised cap admitted more than one"
        );

        l.replace([("r".to_string(), None, cap(2))]);
        drop(third);
        assert!(
            l.check_at(1, "r", t0).is_err(),
            "lowered cap admitted with 2 in flight"
        );
        drop(held);
        assert!(l.check_at(1, "r", t0).is_ok());
    }

    /// Requests admitted while a route had no cap still count once one is set.
    #[test]
    fn requests_admitted_without_a_cap_count_once_one_is_set() {
        let l = RateLimiter::default();
        let t0 = Instant::now();
        l.replace([(
            "r".to_string(),
            None,
            Limit {
                requests_per_minute: 1000,
                max_concurrent: None,
            },
        )]);
        let held = l.check_at(1, "r", t0).unwrap();
        l.replace([("r".to_string(), None, cap(1))]);
        assert!(l.check_at(1, "r", t0).is_err());
        drop(held);
        assert!(l.check_at(1, "r", t0).is_ok());
    }

    /// AGENT-272: concurrent write-then-reload pairs must leave the
    /// limiter on the table's final state, whatever order they finish in.
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn concurrent_reloads_publish_the_latest_table() {
        let dir = tempfile::tempdir().unwrap();
        let pool = crate::migrations::open_and_migrate(&dir.path().join("rl.db"))
            .await
            .unwrap();
        let limits = Arc::new(RateLimits::new(
            RateLimitRepository::new(pool),
            Arc::new(RateLimiter::default()),
        ));
        for round in 0..20 {
            let tasks: Vec<_> = (1..=16u32)
                .map(|rpm| {
                    let limits = limits.clone();
                    tokio::spawn(async move {
                        let limit = Limit {
                            requests_per_minute: rpm,
                            max_concurrent: None,
                        };
                        limits.repo.set("r", None, limit, 0).await.unwrap();
                        limits.reload().await.unwrap();
                    })
                })
                .collect();
            for t in tasks {
                t.await.unwrap();
            }
            let stored = limits.repo.get("r", None).await.unwrap().unwrap();
            let published = limits.limiter.limits.load()["r"][&None];
            assert_eq!(published, stored, "round {round}");
        }
    }

    fn limiter(rpm: u32, concurrent: Option<u32>) -> RateLimiter {
        let l = RateLimiter::default();
        l.replace([(
            "r".to_string(),
            None,
            Limit {
                requests_per_minute: rpm,
                max_concurrent: concurrent,
            },
        )]);
        l
    }

    /// AGENT-272: a hammering agent gets one audit row per slot per
    /// `AUDIT_EVERY`, and the next row counts the refusals in between.
    #[test]
    fn refusals_are_audited_once_a_minute_with_a_count() {
        let l = limiter(1, None);
        // The next refusal at `at`, past any token the bucket refilled.
        let refusal = |agent, at| loop {
            if let Err(e) = l.check_at(agent, "r", at) {
                break e.audit;
            }
        };
        let t0 = Instant::now();
        assert_eq!(refusal(1, t0), Some(0));
        for _ in 0..5 {
            assert_eq!(refusal(1, t0), None);
        }
        // Another agent's slot is audited on its own.
        assert_eq!(refusal(2, t0), Some(0));
        assert_eq!(
            refusal(1, t0 + AUDIT_EVERY - Duration::from_millis(1)),
            None
        );
        let next = t0 + AUDIT_EVERY;
        assert_eq!(refusal(1, next), Some(6));
        assert_eq!(refusal(1, next), None);
    }

    /// Concurrency refusals are coalesced the same way.
    #[test]
    fn concurrency_refusals_are_coalesced_too() {
        let l = limiter(1000, Some(1));
        let t0 = Instant::now();
        let _held = l.check_at(1, "r", t0).unwrap();
        assert_eq!(l.check_at(1, "r", t0).unwrap_err().audit, Some(0));
        assert_eq!(l.check_at(1, "r", t0).unwrap_err().audit, None);
        let next = t0 + AUDIT_EVERY;
        assert_eq!(l.check_at(1, "r", next).unwrap_err().audit, Some(1));
    }

    /// AGENT-272: rate and concurrency refusals keep their own window, so
    /// a concurrency episode right after a rate row still gets a row.
    #[test]
    fn rate_and_concurrency_refusals_have_their_own_windows() {
        let l = limiter(1, Some(1));
        let t0 = Instant::now();
        let held = l.check_at(1, "r", t0).unwrap();
        let busy = l.check_at(1, "r", t0).unwrap_err();
        assert!(busy.concurrency);
        assert_eq!(busy.audit, Some(0));
        assert_eq!(l.check_at(1, "r", t0).unwrap_err().audit, None);
        drop(held);
        let rate = l.check_at(1, "r", t0).unwrap_err();
        assert!(!rate.concurrency);
        assert_eq!(rate.audit, Some(0), "its own first row and count");
        assert_eq!(l.check_at(1, "r", t0).unwrap_err().audit, None);
        // Each kind's next row counts only its own refusals.
        let next = t0 + AUDIT_EVERY;
        let _held = l.check_at(1, "r", next).unwrap();
        assert_eq!(l.check_at(1, "r", next).unwrap_err().audit, Some(1));
    }

    /// A rate refusal undoes the in-flight count it took while checking.
    #[test]
    fn a_rate_refusal_leaks_no_in_flight_count() {
        let l = limiter(1, Some(5));
        let t0 = Instant::now();
        drop(l.check_at(1, "r", t0).unwrap());
        for _ in 0..10 {
            assert!(!l.check_at(1, "r", t0).unwrap_err().concurrency);
        }
        let slots = l.lock();
        let slot = slots.get(&(1, "r".to_string())).unwrap();
        assert_eq!(slot.inflight.load(Ordering::Acquire), 0);
    }

    /// AGENT-272: a changed limit starts a new audit window, so the first
    /// refusal under it is recorded and counts the ones held back before.
    #[test]
    fn a_changed_limit_restarts_the_audit_window() {
        let l = limiter(1, None);
        let t0 = Instant::now();
        l.check_at(1, "r", t0).unwrap();
        assert_eq!(l.check_at(1, "r", t0).unwrap_err().audit, Some(0));
        assert_eq!(l.check_at(1, "r", t0).unwrap_err().audit, None);
        l.replace([(
            "r".to_string(),
            None,
            Limit {
                requests_per_minute: 2,
                max_concurrent: None,
            },
        )]);
        l.check_at(1, "r", t0).unwrap();
        l.check_at(1, "r", t0).unwrap();
        assert_eq!(l.check_at(1, "r", t0).unwrap_err().audit, Some(1));
    }

    #[test]
    fn unlimited_routes_are_admitted() {
        let l = limiter(1, None);
        for _ in 0..10 {
            assert!(l.check(1, "other").unwrap().is_none());
        }
    }

    #[test]
    fn tokens_refill_continuously() {
        let l = limiter(60, None);
        let t0 = Instant::now();
        for _ in 0..60 {
            l.check_at(1, "r", t0).unwrap();
        }
        let refused = l.check_at(1, "r", t0).unwrap_err();
        assert_eq!(refused.retry_after_secs, 1);
        assert!(l.check_at(1, "r", t0 + Duration::from_millis(500)).is_err());
        assert!(l.check_at(1, "r", t0 + Duration::from_millis(1000)).is_ok());
    }

    #[test]
    fn retry_after_is_the_time_to_one_token() {
        let l = limiter(2, None);
        let t0 = Instant::now();
        l.check_at(1, "r", t0).unwrap();
        l.check_at(1, "r", t0).unwrap();
        assert_eq!(l.check_at(1, "r", t0).unwrap_err().retry_after_secs, 30);
        let later = t0 + Duration::from_secs(20);
        assert_eq!(l.check_at(1, "r", later).unwrap_err().retry_after_secs, 10);
    }

    #[test]
    fn a_changed_limit_starts_a_full_bucket() {
        let l = limiter(1, None);
        let t0 = Instant::now();
        l.check_at(1, "r", t0).unwrap();
        assert!(l.check_at(1, "r", t0).is_err());
        l.replace([(
            "r".to_string(),
            Some(1),
            Limit {
                requests_per_minute: 3,
                max_concurrent: None,
            },
        )]);
        for _ in 0..3 {
            l.check_at(1, "r", t0).unwrap();
        }
        assert!(l.check_at(1, "r", t0).is_err());
    }

    #[test]
    fn concurrency_refusal_spends_no_token() {
        let l = limiter(2, Some(1));
        let t0 = Instant::now();
        let held = l.check_at(1, "r", t0).unwrap();
        let refused = l.check_at(1, "r", t0).unwrap_err();
        assert!(refused.concurrency);
        drop(held);
        l.check_at(1, "r", t0).unwrap();
    }

    #[test]
    fn removing_a_route_limit_drops_its_buckets() {
        let l = limiter(1, None);
        l.check(1, "r").unwrap();
        l.replace([]);
        assert!(l.lock().is_empty());
        assert!(l.check(1, "r").unwrap().is_none());
    }
}
