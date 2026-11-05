use super::*;
use crate::oauth::consent::refresh::Trace;
use std::{sync::Mutex, time::Duration};
use tokio::time::Instant;

fn trace() -> Trace {
    Trace {
        stage: Arc::new(Mutex::new("admission")),
        finalization: "not_started",
        cleanup: "not_required",
    }
}
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(40)
}
impl Fixture {
    async fn refreshable(&self, label: &str) -> Value {
        let (_, a) = self.claimed(label).await;
        let token=token::decode(&self.rt.config.profiles[0],br#"{"access_token":"old-synthetic-access","refresh_token":"old-synthetic-refresh","token_type":"Bearer","scope":"read","expires_in":100}"#).unwrap();
        self.rt.publish(&a, &token).await.unwrap();
        self.rt.account("owner", "fixture", label).await.unwrap()
    }
}
#[tokio::test]
async fn claim_completion_revision_optionality_and_non_replay() {
    let f = Fixture::new().await;
    let before = f.refreshable("ready").await;
    let mut t = trace();
    assert!(matches!(
        f.rt.claim_refresh(
            "other",
            "fixture",
            "ready",
            before["revision"].as_str().unwrap(),
            deadline(),
            &mut t
        )
        .await,
        Err(Error("not_found"))
    ));
    let c =
        f.rt.claim_refresh(
            "owner",
            "fixture",
            "ready",
            before["revision"].as_str().unwrap(),
            deadline(),
            &mut t,
        )
        .await
        .unwrap();
    assert_eq!(t.finalization, "pending");
    let pending = f.rt.account("owner", "fixture", "ready").await.unwrap();
    assert_eq!(pending["refresh_pending"], true);
    assert_eq!(pending["token_version"], 1);
    assert_eq!(pending["state"], "reconnect_required");
    assert_ne!(pending["revision"], before["revision"]);
    assert!(
        f.rt.claim_refresh(
            "owner",
            "fixture",
            "ready",
            before["revision"].as_str().unwrap(),
            deadline(),
            &mut trace()
        )
        .await
        .is_err()
    );
    assert!(matches!(
        f.rt.claim_refresh(
            "owner",
            "fixture",
            "ready",
            pending["revision"].as_str().unwrap(),
            deadline(),
            &mut trace()
        )
        .await,
        Err(Error("reconnect_required"))
    ));
    let replacement = token::Token {
        access: "new-synthetic-access".into(),
        refresh: Some("new-synthetic-refresh".into()),
        expiry: None,
        scope_echoed: false,
    };
    let done =
        f.rt.complete_refresh(&c, &replacement, &mut t)
            .await
            .unwrap();
    assert_eq!(done["token_version"], 2);
    assert_eq!(done["account_generation"], before["account_generation"]);
    assert_eq!(done["refresh_pending"], false);
    assert_eq!(done["token_expires_at"], Value::Null);
    assert_eq!(done["granted_scope"], Value::Null);
    assert!(
        f.rt.complete_refresh(&c, &replacement, &mut t)
            .await
            .is_err()
    );
    let row = sqlx::query("SELECT * FROM oauth_sessions WHERE session_label='ready'")
        .fetch_one(&f.rt.pool)
        .await
        .unwrap();
    assert_eq!(
        f.rt.key
            .unseal(
                row.get("refresh_token_ciphertext"),
                row.get("refresh_token_nonce")
            )
            .unwrap(),
        b"new-synthetic-refresh"
    );
    f.rt.pool.close().await;
}
#[tokio::test]
async fn current_match_aba_disconnect_and_unrelated_progress() {
    for action in ["disconnect", "registration"] {
        let f = Fixture::new().await;
        let first = f.refreshable("one").await;
        let registration = f.repo.get("fixture").await.unwrap().unwrap();
        f.repo.delete("fixture").await.unwrap();
        f.repo.create(&registration).await.unwrap();
        assert!(
            f.rt.claim_refresh(
                "owner",
                "fixture",
                "one",
                first["revision"].as_str().unwrap(),
                deadline(),
                &mut trace()
            )
            .await
            .is_err()
        );
        let fresh = f.rt.account("owner", "fixture", "one").await.unwrap();
        let c =
            f.rt.claim_refresh(
                "owner",
                "fixture",
                "one",
                fresh["revision"].as_str().unwrap(),
                deadline(),
                &mut trace(),
            )
            .await
            .unwrap();
        // No transaction remains held after claim; independent custody progresses.
        f.refreshable("two").await;
        if action == "disconnect" {
            let pending = f.rt.account("owner", "fixture", "one").await.unwrap();
            f.rt.disconnect(
                "owner",
                "fixture",
                "one",
                pending["revision"].as_str().unwrap(),
            )
            .await
            .unwrap();
            let new = f.refreshable("one").await;
            assert_ne!(new["account_generation"], first["account_generation"]);
        } else {
            f.repo.delete("fixture").await.unwrap();
            f.repo.create(&registration).await.unwrap();
        }
        assert!(f.rt.check_refresh(&c).await.is_err());
        assert!(
            f.rt.complete_refresh(
                &c,
                &token::Token {
                    access: "late".into(),
                    refresh: Some("late-refresh".into()),
                    expiry: None,
                    scope_echoed: false
                },
                &mut trace()
            )
            .await
            .is_err()
        );
        f.rt.pool.close().await;
    }
}
#[tokio::test]
async fn deferred_commit_and_exhaustion_preserve_uncertainty() {
    let f = Fixture::new().await;
    let before = f.refreshable("fault").await;
    for sql in [
        "CREATE TABLE refresh_parent(id INTEGER PRIMARY KEY)",
        "CREATE TABLE refresh_child(id INTEGER REFERENCES refresh_parent(id) DEFERRABLE INITIALLY DEFERRED)",
        "CREATE TRIGGER refresh_deferred AFTER UPDATE ON oauth_sessions WHEN NEW.refresh_pending=1 BEGIN INSERT INTO refresh_child VALUES(1); END",
    ] {
        f.rt.pool.execute(sql).await.unwrap();
    }
    let mut t = trace();
    assert!(matches!(
        f.rt.claim_refresh(
            "owner",
            "fixture",
            "fault",
            before["revision"].as_str().unwrap(),
            deadline(),
            &mut t
        )
        .await,
        Err(Error("commit_unknown"))
    ));
    assert_eq!(
        f.rt.account("owner", "fixture", "fault").await.unwrap(),
        before
    );
    f.rt.pool
        .execute("DROP TRIGGER refresh_deferred")
        .await
        .unwrap();
    let c =
        f.rt.claim_refresh(
            "owner",
            "fixture",
            "fault",
            before["revision"].as_str().unwrap(),
            deadline(),
            &mut trace(),
        )
        .await
        .unwrap();
    // A distinct name: a pooled connection can still cache the schema from
    // before the DROP above, and SQLite checks "already exists" against that
    // cache at prepare time without reloading it.
    f.rt.pool.execute("CREATE TRIGGER refresh_deferred_completion AFTER UPDATE ON oauth_sessions WHEN NEW.refresh_pending=0 BEGIN INSERT INTO refresh_child VALUES(1); END").await.unwrap();
    let replacement = token::Token {
        access: "new".into(),
        refresh: Some("new-refresh".into()),
        expiry: None,
        scope_echoed: false,
    };
    assert_eq!(
        f.rt.complete_refresh(&c, &replacement, &mut trace())
            .await
            .unwrap_err()
            .0,
        "commit_unknown"
    );
    let pending = f.rt.account("owner", "fixture", "fault").await.unwrap();
    assert_eq!(pending["refresh_pending"], true);
    assert_eq!(pending["token_version"], 1);
    let next = Runtime::new(
        f.rt.pool.clone(),
        f.rt.key.clone(),
        f.rt.config.clone(),
        RefreshOwner::default(),
    )
    .await
    .unwrap();
    assert_eq!(
        next.account("owner", "fixture", "fault").await.unwrap(),
        pending
    );
    f.rt.pool
        .execute("DROP TRIGGER refresh_deferred_completion")
        .await
        .unwrap();
    sqlx::query("UPDATE oauth_sessions SET refresh_pending=0, token_version=?")
        .bind(i64::MAX - 1)
        .execute(&f.rt.pool)
        .await
        .unwrap();
    let exhausted = f.rt.account("owner", "fixture", "fault").await.unwrap();
    assert_eq!(exhausted["state"], "reconnect_required");
    assert_eq!(exhausted["refresh_unavailable_reason"], "version_exhausted");
    assert!(matches!(
        f.rt.claim_refresh(
            "owner",
            "fixture",
            "fault",
            exhausted["revision"].as_str().unwrap(),
            deadline(),
            &mut trace()
        )
        .await,
        Err(Error("version_exhausted"))
    ));
    f.rt.pool.close().await;
}

#[path = "process.rs"]
mod process;

#[tokio::test]
async fn deadline_guard_refuses_after_database_await_and_preserves_control() {
    use sqlx::{
        Connection, SqliteConnection,
        sqlite::{SqliteConnectOptions, SqliteJournalMode},
    };
    let f = Fixture::new().await;
    let before = f.refreshable("deadline").await;
    let mut claim =
        f.rt.claim_refresh(
            "owner",
            "fixture",
            "deadline",
            before["revision"].as_str().unwrap(),
            deadline(),
            &mut trace(),
        )
        .await
        .unwrap();
    f.rt.pool.close().await;
    // Test-only DELETE journal creates a controlled reader wait. This observes
    // the guard boundary, not a shipping-WAL delay or a late endpoint send.
    let options = SqliteConnectOptions::new()
        .filename(f._dir.path().join("state.db"))
        .journal_mode(SqliteJournalMode::Delete)
        .busy_timeout(Duration::from_secs(2));
    let mut reader = SqliteConnection::connect_with(&options).await.unwrap();
    let mut writer = SqliteConnection::connect_with(&options).await.unwrap();
    writer.execute("BEGIN EXCLUSIVE").await.unwrap();
    claim.deadline = Instant::now() + Duration::from_millis(100);
    let result = {
        let guard = f.rt.current_refresh(&mut reader, &claim);
        tokio::pin!(guard);
        let first =
            std::future::poll_fn(|cx| std::task::Poll::Ready(guard.as_mut().poll(cx))).await;
        assert!(first.is_pending(), "guard must reach its database await");
        assert!(Instant::now() < claim.deadline);
        tokio::time::sleep_until(claim.deadline + Duration::from_millis(20)).await;
        writer.execute("ROLLBACK").await.unwrap();
        guard.await
    };
    claim.deadline = deadline();
    assert!(
        f.rt.current_refresh(&mut reader, &claim).await.is_ok(),
        "pre-expiry positive control"
    );
    reader.close().await.unwrap();
    writer.close().await.unwrap();
    assert!(
        matches!(result, Err(Error("operation_incomplete"))),
        "expired post-read guard returned {result:?}"
    );
}
