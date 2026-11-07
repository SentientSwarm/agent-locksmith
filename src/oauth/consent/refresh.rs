//! Manual controlled refresh. A durable pending row is never a runnable claim.
use super::*;
use secrecy::ExposeSecret;
use serde_json::json;
use sqlx::{SqliteConnection, sqlite::SqliteRow};
use std::{sync::Mutex, time::Duration};
use tokio::time::Instant;

mod custody;

pub(super) struct Claim {
    owner: String,
    name: String,
    label: String,
    generation: i64,
    version: i64,
    pub(super) profile_id: String,
    profile_digest: String,
    registration: (String, i64),
    token_client: reqwest::Client,
    pub(super) wire_client: locksmith_mcp_transport::Client,
    old: token::Token,
    client_secret: Option<secrecy::SecretString>,
    pub(super) deadline: Instant,
}
#[derive(Clone)]
pub(super) struct Trace {
    pub(super) stage: Arc<Mutex<&'static str>>,
    pub(super) finalization: &'static str,
    pub(super) cleanup: &'static str,
}
impl Trace {
    fn enter(&self, phase: &'static str) {
        *self.stage.lock().expect("refresh stage") = phase;
    }
    fn value(&self, result: &Result<Value>) -> Value {
        let uncertain = matches!(self.finalization, "pending" | "commit_unknown");
        json!({"outcome":if result.is_ok() {"committed"} else if uncertain {"unknown"} else {"refused"},
            "stage":*self.stage.lock().expect("refresh stage"),"safe_reason":result.as_ref().err().map(|e| e.0),
            "cleanup":self.cleanup,"finalization":self.finalization})
    }
}
impl Runtime {
    /// The admin middleware owns this entire future, including cleanup.
    pub(super) async fn refresh(
        &self,
        owner: &str,
        name: &str,
        label: &str,
        expected: &str,
    ) -> (Result<Value>, Value) {
        let deadline = Instant::now() + Duration::from_secs(40);
        let mut trace = Trace {
            stage: Arc::new(Mutex::new("admission")),
            finalization: "not_started",
            cleanup: "not_required",
        };
        let mut checked = None;
        let result = tokio::time::timeout_at(deadline, async {
            let claim = self
                .claim_refresh(owner, name, label, expected, deadline, &mut trace)
                .await?;
            #[cfg(test)]
            crate::oauth::refresh::recovery_barrier::reach("controlled_claimed").await;
            trace.enter("token");
            self.check_refresh(&claim).await?;
            let profile = self.profile(&claim.profile_id)?;
            let token = token::refresh(
                profile,
                &claim.token_client,
                &claim.old,
                claim.client_secret.as_ref().map(|v| v.expose_secret()),
            )
            .await?;
            #[cfg(test)]
            crate::oauth::refresh::recovery_barrier::reach("controlled_received").await;
            self.check_refresh(&claim).await?;
            let mut wire = wire::Wire::refresh(
                self,
                &claim,
                token.access.expose_secret(),
                trace.stage.clone(),
            )?;
            let result =
                match operation::identity(&mut wire, profile, &token, Some(&claim.old)).await {
                    Ok(subject) => {
                        trace.enter("commit");
                        self.complete_refresh(&claim, &token, subject.as_ref(), &mut trace)
                            .await
                    }
                    Err(error) => Err(error),
                };
            checked = Some(result.clone());
            trace.cleanup = "incomplete";
            trace.cleanup = tokio::time::timeout_at(
                deadline.min(Instant::now() + Duration::from_secs(6)),
                wire.close(),
            )
            .await
            .unwrap_or("incomplete");
            result
        })
        .await;
        let result = match result {
            Ok(r) => r,
            Err(_) => checked.unwrap_or(Err(Error("operation_incomplete"))),
        };
        (result.clone(), trace.value(&result))
    }

    pub(super) async fn check_refresh(&self, claim: &Claim) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        self.current_refresh(&mut tx, claim).await
    }
    pub(in crate::oauth::consent) async fn current_refresh(
        &self,
        c: &mut SqliteConnection,
        claim: &Claim,
    ) -> Result<()> {
        if Instant::now() >= claim.deadline {
            return Err(Error("operation_incomplete"));
        }
        let row = sqlx::query("SELECT * FROM oauth_sessions WHERE name=? AND session_label=?")
            .bind(&claim.name)
            .bind(&claim.label)
            .fetch_optional(&mut *c)
            .await?
            .ok_or(Error("source_conflict"))?;
        let profile = self.profile(&claim.profile_id)?;
        clients::current(c, &claim.owner, profile).await?;
        if !config::managed_kind(row.get("kind"))
            || row.get::<Option<&str>, _>("owner_id") != Some(&claim.owner)
            || row.get::<i64, _>("incarnation") != claim.generation
            || row.get::<i64, _>("token_version") != claim.version
            || !row.get::<bool, _>("refresh_pending")
            || row.get::<bool, _>("degraded")
            || row.get::<Option<&str>, _>("profile_id") != Some(&claim.profile_id)
            || !account::profile_matches(&row, profile)?
            || profile.digest()? != claim.profile_digest
            || store::registration(c, &claim.name, Some(profile)).await? != claim.registration
        {
            return Err(Error("source_conflict"));
        }
        // Database waits and scheduling count against the original deadline.
        if Instant::now() >= claim.deadline {
            return Err(Error("operation_incomplete"));
        }
        Ok(())
    }
}
