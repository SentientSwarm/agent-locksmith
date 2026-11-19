use super::*;

#[test]
fn safety_margin_uses_five_minutes_for_long_lifetime() {
    // 1-hour token: lifetime/4 = 900s; capped at 300s.
    assert_eq!(refresh_safety_margin_secs(3600), 300);
    // 24-hour token: lifetime/4 = 21600s; capped at 300s.
    assert_eq!(refresh_safety_margin_secs(86400), 300);
}

#[test]
fn safety_margin_uses_quarter_for_short_lifetime() {
    // 15-min token: lifetime/4 = 225s; floor at 60s; chosen 225.
    assert_eq!(refresh_safety_margin_secs(900), 225);
}

#[test]
fn safety_margin_floors_at_sixty() {
    // 2-min token: lifetime/4 = 30s; floored to 60s.
    assert_eq!(refresh_safety_margin_secs(120), 60);
    // 30-second token (pathological): lifetime/4 = 7s; floor 60s.
    assert_eq!(refresh_safety_margin_secs(30), 60);
}

#[tokio::test]
async fn lock_map_returns_same_lock_for_same_name_and_label() {
    let map = RefreshLockMap::new();
    let l1 = map.get("codex", "default").await;
    let l2 = map.get("codex", "default").await;
    assert!(Arc::ptr_eq(&l1, &l2));

    let l3 = map.get("anthropic-oauth", "default").await;
    assert!(!Arc::ptr_eq(&l1, &l3));
}

// Phase G: distinct labels under the same registration name get
// distinct locks, so two labels can refresh concurrently without
// serializing on each other.
#[tokio::test]
async fn lock_map_distinguishes_labels_under_same_name() {
    let map = RefreshLockMap::new();
    let l_default = map.get("codex", "default").await;
    let l_hermes = map.get("codex", "hermes").await;
    let l_openclaw = map.get("codex", "openclaw").await;
    assert!(!Arc::ptr_eq(&l_default, &l_hermes));
    assert!(!Arc::ptr_eq(&l_hermes, &l_openclaw));
    assert!(!Arc::ptr_eq(&l_default, &l_openclaw));
}

/// AGENT-302 — a token call that fails after its claim leaves the session
/// `reconnect_required` (custody is uncertain), so it can't be marked
/// degraded; it must still reach the operational log.
mod failure_events {
    use super::super::record_failure;
    use super::*;
    use crate::migrations::open_and_migrate;
    use crate::operational_log_sink::OperationalLogEmitter;
    use crate::repo::{LogFilter, OperationalLogRecord, OperationalLogStore};
    use tempfile::TempDir;

    async fn setup() -> (
        TempDir,
        OauthSessionRepository,
        SealingKey,
        OperationalLogStore,
    ) {
        let dir = TempDir::new().unwrap();
        let pool = open_and_migrate(&dir.path().join("db.sqlite"))
            .await
            .unwrap();
        let key = SealingKey::generate().unwrap();
        (
            dir,
            OauthSessionRepository::new(pool.clone()),
            key,
            OperationalLogStore::new(pool),
        )
    }

    async fn logged(store: &OperationalLogStore) -> Vec<OperationalLogRecord> {
        let filter = LogFilter {
            limit: 10,
            ..LogFilter::default()
        };
        for _ in 0..100 {
            let rows = store.query(&filter).await.unwrap();
            if !rows.is_empty() {
                return rows;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        Vec::new()
    }

    #[tokio::test]
    async fn a_failure_after_the_claim_is_logged_as_reconnect_required() {
        let (_d, repo, key, store) = setup().await;
        let log = OperationalLogEmitter::spawn(store.clone(), 16);
        let session = repo
            .create(&key, "codex", "default", "rt", Some("at"), Some(1), "")
            .await
            .unwrap();
        repo.begin_refresh(&key, &session).await.unwrap();
        let error = RefreshError::Revoked { status: 401 };
        record_failure(&repo, &session, &error, Some(&log)).await;
        let rows = logged(&store).await;
        assert_eq!(rows.len(), 1, "{rows:?}");
        assert_eq!(rows[0].event, "oauth_refresh_reconnect_required");
        assert_eq!(rows[0].level, "warn");
        let fields = rows[0].fields.clone().unwrap();
        assert_eq!(fields["registration"], "codex");
        assert_eq!(fields["session_label"], "default");
        assert_eq!(fields["cause"], "revoked");
    }

    #[tokio::test]
    async fn a_provider_answer_logs_its_status() {
        // AGENT-328: a 300 or 304 is `provider_5xx` like a 5xx, so only the
        // status in `fields` tells the operator which it was.
        let (_d, repo, key, store) = setup().await;
        let log = OperationalLogEmitter::spawn(store.clone(), 16);
        let session = repo
            .create(&key, "codex", "default", "rt", Some("at"), Some(1), "")
            .await
            .unwrap();
        repo.begin_refresh(&key, &session).await.unwrap();
        let error = RefreshError::ProviderError { status: 304 };
        record_failure(&repo, &session, &error, Some(&log)).await;
        let rows = logged(&store).await;
        assert_eq!(rows.len(), 1, "{rows:?}");
        let fields = rows[0].fields.clone().unwrap();
        assert_eq!(fields["cause"], "provider_5xx");
        assert_eq!(fields["http_status"], 304);
    }

    #[tokio::test]
    async fn a_failure_before_the_claim_is_logged_as_degraded() {
        let (_d, repo, key, store) = setup().await;
        let log = OperationalLogEmitter::spawn(store.clone(), 16);
        let session = repo
            .create(&key, "codex", "default", "rt", Some("at"), Some(1), "")
            .await
            .unwrap();
        let error = RefreshError::BadResponse("empty refresh token".into());
        record_failure(&repo, &session, &error, Some(&log)).await;
        let rows = logged(&store).await;
        assert_eq!(rows.len(), 1, "{rows:?}");
        assert_eq!(rows[0].event, "oauth_refresh_degraded");
        // No provider answer, so no status.
        let fields = rows[0].fields.clone().unwrap();
        assert!(fields.get("http_status").is_none(), "{fields}");
    }

    #[tokio::test]
    async fn a_recreated_session_claimed_at_the_same_version_is_not_ours() {
        // Revoked and signed in again, then claimed by another refresh: the
        // new row has this claim's token version but another incarnation.
        let (_d, repo, key, store) = setup().await;
        let log = OperationalLogEmitter::spawn(store.clone(), 16);
        let old = repo
            .create(&key, "codex", "default", "rt", Some("at"), Some(1), "")
            .await
            .unwrap();
        repo.delete(&old.name, &old.session_label).await.unwrap();
        let new = repo
            .create(&key, "codex", "default", "rt2", Some("at"), Some(1), "")
            .await
            .unwrap();
        assert_eq!(new.token_version, old.token_version);
        assert_ne!(new.incarnation, old.incarnation);
        repo.begin_refresh(&key, &new).await.unwrap();
        assert!(!repo.held_by_claim(&old).await.unwrap());
        record_failure(
            &repo,
            &old,
            &RefreshError::Revoked { status: 401 },
            Some(&log),
        )
        .await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        let filter = LogFilter {
            limit: 10,
            ..LogFilter::default()
        };
        assert!(store.query(&filter).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_session_changed_by_someone_else_logs_nothing() {
        // A revoke (or a new sign-in) between the read and the failure is
        // not this refresh's outcome to report.
        let (_d, repo, key, store) = setup().await;
        let log = OperationalLogEmitter::spawn(store.clone(), 16);
        let session = repo
            .create(&key, "codex", "default", "rt", Some("at"), Some(1), "")
            .await
            .unwrap();
        repo.delete(&session.name, &session.session_label)
            .await
            .unwrap();
        let error = RefreshError::Revoked { status: 401 };
        record_failure(&repo, &session, &error, Some(&log)).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        let filter = LogFilter {
            limit: 10,
            ..LogFilter::default()
        };
        assert!(store.query(&filter).await.unwrap().is_empty());
    }

    /// Captures formatted log lines for one test.
    #[derive(Clone, Default)]
    struct Captured(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for Captured {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn the_daemon_log_names_the_provider_status() {
        // AGENT-328: when the session changed under the failure, nothing
        // reaches the operational log, so the daemon log is the only record
        // and must say a 304 from a 503.
        let (_d, repo, key, _store) = setup().await;
        let session = repo
            .create(&key, "codex", "default", "rt", Some("at"), Some(1), "")
            .await
            .unwrap();
        repo.delete(&session.name, &session.session_label)
            .await
            .unwrap();
        let captured = Captured::default();
        let writer = captured.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(move || writer.clone())
            .with_ansi(false)
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);
        let error = RefreshError::ProviderError { status: 304 };
        record_failure(&repo, &session, &error, None).await;
        let text = String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
        assert!(text.contains("degradation not committed"), "{text}");
        assert!(text.contains("http_status=Some(304)"), "{text}");
    }
}
