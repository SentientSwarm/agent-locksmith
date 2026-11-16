//! AGENT-266 — per-agent, per-route rate limits.
//!
//! Limits live in the `rate_limits` table (migration 0027) and are
//! mirrored here so the proxy checks them without a query. A route
//! default applies to every agent separately; an agent row overrides it.
//! Each (agent, route) gets a token bucket of `requests_per_minute`
//! tokens, refilled continuously, and, with `max_concurrent`, a
//! semaphore whose permit the request holds until its body is dropped.

pub mod repo;

use arc_swap::ArcSwap;
use serde::Serialize;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

pub use repo::{RateLimitRepository, RateLimitRow};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Limit {
    pub requests_per_minute: u32,
    pub max_concurrent: Option<u32>,
}

/// Why a request was refused, and when a retry can succeed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limited {
    pub retry_after_secs: u64,
    pub concurrency: bool,
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
    inflight: Option<Arc<Semaphore>>,
}

impl Slot {
    fn new(limit: Limit, now: Instant) -> Self {
        Self {
            limit,
            tokens: f64::from(limit.requests_per_minute),
            at: now,
            inflight: semaphore(limit),
        }
    }

    /// A changed limit starts a fresh bucket; a changed concurrency cap a
    /// fresh semaphore (permits already out return to the old one).
    fn adopt(&mut self, limit: Limit, now: Instant) {
        if self.limit.requests_per_minute != limit.requests_per_minute {
            self.tokens = f64::from(limit.requests_per_minute);
            self.at = now;
        }
        if self.limit.max_concurrent != limit.max_concurrent {
            self.inflight = semaphore(limit);
        }
        self.limit = limit;
    }
}

fn semaphore(limit: Limit) -> Option<Arc<Semaphore>> {
    limit
        .max_concurrent
        .map(|n| Arc::new(Semaphore::new(n as usize)))
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
    /// holds a concurrency slot until the permit is dropped.
    pub fn check(&self, agent: i64, route: &str) -> Result<Option<OwnedSemaphorePermit>, Limited> {
        self.check_at(agent, route, Instant::now())
    }

    fn check_at(
        &self,
        agent: i64,
        route: &str,
        now: Instant,
    ) -> Result<Option<OwnedSemaphorePermit>, Limited> {
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
        let permit = match &slot.inflight {
            Some(sem) => match sem.clone().try_acquire_owned() {
                Ok(p) => Some(p),
                Err(_) => {
                    return Err(Limited {
                        retry_after_secs: 1,
                        concurrency: true,
                    });
                }
            },
            None => None,
        };
        let rate = f64::from(limit.requests_per_minute) / 60.0;
        let elapsed = now.saturating_duration_since(slot.at).as_secs_f64();
        slot.tokens = (slot.tokens + elapsed * rate).min(f64::from(limit.requests_per_minute));
        slot.at = now;
        if slot.tokens < 1.0 {
            // The epsilon keeps float error from adding a second.
            let wait = ((1.0 - slot.tokens) / rate - 1e-9).ceil() as u64;
            return Err(Limited {
                retry_after_secs: wait.max(1),
                concurrency: false,
            });
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
