use super::*;
use sqlx::sqlite::SqliteRow;
use std::{sync::Mutex, time::Duration};

impl Runtime {
    pub(super) async fn callback(
        &self,
        state: &str,
        issuer: Option<&str>,
        code: Option<&str>,
        authority: &str,
        path: &str,
    ) -> Result<()> {
        let _permit = self
            .operations
            .try_acquire()
            .map_err(|_| Error("capacity"))?;
        let outer_deadline = tokio::time::Instant::now() + Duration::from_secs(40);
        let attempt =
            tokio::time::timeout_at(outer_deadline, self.claim(state, issuer, authority, path))
                .await
                .map_err(|_| Error("operation_incomplete"))??;
        self.callback_claimed(&attempt, code, outer_deadline).await
    }

    async fn callback_claimed(
        &self,
        attempt: &SqliteRow,
        code: Option<&str>,
        outer_deadline: tokio::time::Instant,
    ) -> Result<()> {
        let id: &str = attempt.get("id");
        if code.is_none() {
            self.fail(id, "callback", "authorization_denied").await?;
            return Err(Error("authorization_denied"));
        }
        let deadline = outer_deadline.min(
            tokio::time::Instant::now()
                + Duration::from_secs((attempt.get::<i64, _>("deadline") - now()).max(0) as u64),
        );
        self.callback_result(attempt, code.unwrap(), deadline).await
    }

    // The stage lives outside the timed future; timeout does not erase it.
    async fn callback_result(
        &self,
        attempt: &SqliteRow,
        code: &str,
        deadline: tokio::time::Instant,
    ) -> Result<()> {
        let id: &str = attempt.get("id");
        let stage = Arc::new(Mutex::new("claimed"));
        let checked = Arc::new(Mutex::new(None));
        let result = tokio::time::timeout_at(
            deadline,
            self.operate(attempt, code, stage.clone(), checked.clone()),
        )
        .await;
        let result = match result {
            Ok(result) => result,
            Err(_) => checked
                .lock()
                .expect("checked outcome")
                .unwrap_or(Err(Error("operation_incomplete"))),
        };
        if let Err(error) = result {
            let phase = *stage.lock().expect("stage");
            // A submitted COMMIT may have succeeded. Never change a connected
            // attempt, and retain the primary reason even if this write fails.
            let _ =
                tokio::time::timeout(Duration::from_secs(5), self.fail(id, phase, error.0)).await;
        }
        result
    }
}
