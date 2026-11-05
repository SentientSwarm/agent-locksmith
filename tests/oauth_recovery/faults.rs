use super::support::*;

async fn fixture() -> (sqlx::SqlitePool, OauthSessionRepository, SealingKey) {
    let pool = migrations::open_and_migrate(std::path::Path::new(":memory:"))
        .await
        .unwrap();
    let repo = OauthSessionRepository::new(pool.clone());
    (pool, repo, SealingKey::generate().unwrap())
}

async fn fault(pool: &sqlx::SqlitePool, stage: &str) {
    let sql = match stage {
        "write" => {
            "CREATE TRIGGER fault BEFORE UPDATE ON oauth_sessions BEGIN SELECT RAISE(ABORT, 'synthetic'); END;"
        }
        "decode" => "UPDATE oauth_sessions SET refresh_token_ciphertext=X'00';",
        "commit" => {
            "CREATE TABLE parent(id INTEGER PRIMARY KEY); CREATE TABLE fail(id INTEGER REFERENCES parent(id) DEFERRABLE INITIALLY DEFERRED); CREATE TRIGGER fault AFTER UPDATE ON oauth_sessions BEGIN INSERT INTO fail VALUES(1); END;"
        }
        _ => unreachable!(),
    };
    sqlx::raw_sql(sql).execute(pool).await.unwrap();
}

async fn state(pool: &sqlx::SqlitePool) -> (i64, i64, Vec<u8>, Vec<u8>) {
    sqlx::query_as("SELECT refresh_pending, token_version, access_token_ciphertext, refresh_token_ciphertext FROM oauth_sessions").fetch_one(pool).await.unwrap()
}

#[tokio::test]
async fn claim_write_decode_and_commit_failures_send_nothing() {
    for stage in ["write", "decode", "commit"] {
        let (db, repo, key) = fixture().await;
        let old = seed(&repo, &key).await;
        fault(&db, stage).await;
        let before = state(&db).await;
        let server = MockServer::start().await;
        assert!(
            refresh_selected_session(
                &repo,
                &selection(&server),
                &key,
                &reqwest::Client::new(),
                &old
            )
            .await
            .is_err()
        );
        assert!(server.received_requests().await.unwrap().is_empty());
        assert_eq!(
            state(&db).await,
            before,
            "claim {stage} failure mutated custody"
        );
    }
}

#[tokio::test]
async fn completion_write_decode_and_commit_failures_preserve_uncertainty() {
    for stage in ["write", "decode", "commit"] {
        let (db, repo, key) = fixture().await;
        let old = seed(&repo, &key).await;
        let attempt = repo.begin_refresh(&key, &old).await.unwrap();
        fault(&db, stage).await;
        let before = state(&db).await;
        // Omitted refresh forces decode of the stored refresh ciphertext.
        assert!(
            repo.complete_refresh(&key, &attempt, "uncommitted-access", 9999, None)
                .await
                .is_err()
        );
        assert_eq!(
            state(&db).await,
            before,
            "completion {stage} failure changed pair"
        );
        assert_eq!(before.0, 1);
    }
}
