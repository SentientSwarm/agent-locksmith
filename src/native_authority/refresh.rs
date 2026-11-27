//! AGENT-378: an agent's own request refreshes a stale observation.
//!
//! Runs before the agent's effective snapshot (list) and dispatch capture, as
//! that agent, through its own delegation. It never fails the caller: when it
//! can't or mustn't refresh, today's freshness checks produce today's errors.
use super::{
    Result,
    runtime::Runtime,
    source::Current,
    store::{self, Candidate, Renewal},
};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

/// After a failed refresh, no new attempt for that key for this long.
const BACKOFF: Duration = Duration::from_secs(5);
type Gate = Arc<tokio::sync::Mutex<Option<Instant>>>;

/// One refresh at a time per (instance, account_key), with its last failure.
#[derive(Default)]
pub struct Refreshes(Mutex<HashMap<(String, String), Gate>>);
impl Refreshes {
    fn gate(&self, current: &Current) -> Gate {
        let key = (
            current.source.instance.clone(),
            current.source.account_key.clone(),
        );
        self.0.lock().unwrap().entry(key).or_default().clone()
    }
}

impl Runtime {
    pub async fn ensure_fresh(&self, agent: &str, name: &str) {
        let Ok(Some((current, _))) = self.candidate(agent, name).await else {
            return;
        };
        let gate = self.refreshes.gate(&current);
        let mut failed = gate.lock().await;
        if failed.is_some_and(|t| t.elapsed() < BACKOFF) {
            return;
        }
        // A waiter ahead of us may have refreshed it already.
        let Ok(Some((current, candidate))) = self.candidate(agent, name).await else {
            return;
        };
        let age = store::now() - candidate.observed_at;
        // The upstream client future is large; keep it off the caller's stack.
        match Box::pin(self.renew_upstream(agent, name, &current, &candidate)).await {
            Ok(Renewal::Unchanged) => {
                *failed = None;
                tracing::info!(
                    connection = name,
                    agent,
                    outcome = "unchanged",
                    age,
                    "native_observation_refreshed"
                );
            }
            Ok(Renewal::Changed { invalidated }) => {
                *failed = None;
                tracing::warn!(
                    connection = name,
                    agent,
                    outcome = "changed",
                    invalidated,
                    age,
                    "native_observation_refreshed"
                );
            }
            Err(error) => {
                *failed = Some(Instant::now());
                tracing::warn!(
                    connection = name,
                    agent,
                    code = error.0,
                    age,
                    "native_observation_refresh_failed"
                );
            }
        }
    }
    async fn candidate(&self, agent: &str, name: &str) -> Result<Option<(Current, Candidate)>> {
        let mut tx = self.repo.pool.begin().await?;
        let current = self.current(&mut tx, agent, name).await?;
        let found = store::candidate(&mut tx, &current, &self.run, current.agent).await?;
        tx.commit().await?;
        Ok(found.map(|c| (current, c)))
    }
    async fn renew_upstream(
        &self,
        agent: &str,
        name: &str,
        before: &Current,
        candidate: &Candidate,
    ) -> Result<Renewal> {
        let manifest = self.collect(None, agent, name, before).await?;
        let mut tx = self.repo.pool.begin_with("BEGIN IMMEDIATE").await?;
        let current = self.current(&mut tx, agent, name).await?;
        current.matches(&before.source)?;
        let renewal = store::renew(
            &mut tx,
            &current,
            &self.run,
            &candidate.generation,
            &manifest,
        )
        .await?;
        current.fresh()?;
        tx.commit().await?;
        Ok(renewal)
    }
}
