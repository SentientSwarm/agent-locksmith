//! Controlled consent persistence; legacy bytes and non-reused identities matter.
use agent_locksmith::{
    migrations,
    oauth::{OauthSessionRepository, SealingKey},
};
use sqlx::{Connection, Row};

type Error = Box<dyn std::error::Error + Send + Sync>;

#[tokio::test]
async fn migration_preserves_deleted_highwater_and_legacy_bytes() -> Result<(), Error> {
    for keep_row in [false, true] {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("state.db");
        let options = sqlx::sqlite::SqliteConnectOptions::new()
            .filename(&path)
            .create_if_missing(true);
        let mut old_db = sqlx::SqliteConnection::connect_with(&options).await?;
        let mut old = sqlx::migrate!();
        old.migrations = old
            .iter()
            .filter(|m| m.version <= 14)
            .cloned()
            .collect::<Vec<_>>()
            .into();
        old.run(&mut old_db).await?;
        sqlx::query("INSERT INTO oauth_sessions(incarnation,name,session_label,refresh_token_ciphertext,refresh_token_nonce,created_at,updated_at,refresh_pending,token_version) VALUES(7,'kept','label',X'0102',X'0304',12,34,1,5),(99,'gone','label',X'05',X'06',12,34,0,0)")
            .execute(&mut old_db).await?;
        sqlx::query("DELETE FROM oauth_sessions WHERE incarnation=99 OR ?=0")
            .bind(keep_row)
            .execute(&mut old_db)
            .await?;
        old_db.close().await?;
        let pool = migrations::open_and_migrate(&path).await?;
        // New capability control: the prior schema has no kind column.
        let count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM oauth_sessions WHERE kind='legacy'")
                .fetch_one(&pool)
                .await?;
        assert_eq!(count, i64::from(keep_row));
        if keep_row {
            let r = sqlx::query("SELECT hex(refresh_token_ciphertext) ct, hex(refresh_token_nonce) n, refresh_pending, token_version, incarnation FROM oauth_sessions WHERE name='kept'")
                .fetch_one(&pool).await?;
            assert_eq!(r.get::<String, _>("ct"), "0102");
            assert_eq!(r.get::<String, _>("n"), "0304");
            assert_eq!(r.get::<i64, _>("refresh_pending"), 1);
            assert_eq!(r.get::<i64, _>("token_version"), 5);
            assert_eq!(r.get::<i64, _>("incarnation"), 7);
        }
        let repo = OauthSessionRepository::new(pool.clone());
        let key = SealingKey::generate()?;
        let inserted = repo
            .create(&key, "fresh", "label", "fixture-refresh", None, None, "")
            .await?;
        assert!(inserted.incarnation > 99, "deleted history cannot repeat");
        assert!(matches!(
            old.run(&pool).await,
            Err(sqlx::migrate::MigrateError::VersionMissing(15))
        ));
        pool.close().await;
    }
    Ok(())
}

#[tokio::test]
async fn controlled_pending_migration_preserves_all_columns_and_deleted_highwater()
-> Result<(), Error> {
    for keep in [false, true] {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("state.db");
        let mut old = sqlx::migrate!();
        old.migrations = old
            .iter()
            .filter(|m| m.version <= 15)
            .cloned()
            .collect::<Vec<_>>()
            .into();
        let mut c = sqlx::SqliteConnection::connect_with(
            &sqlx::sqlite::SqliteConnectOptions::new()
                .filename(&path)
                .create_if_missing(true),
        )
        .await?;
        old.run(&mut c).await?;
        sqlx::query("INSERT INTO oauth_sessions(incarnation,name,session_label,kind,owner_id,profile_id,profile_digest,workspace_id,user_id,access_token_ciphertext,access_token_nonce,created_at,updated_at,token_version) VALUES(7,'controlled','label','controlled_linear_v1','owner','profile','digest','workspace','user',X'0102',X'0304',12,34,8)").execute(&mut c).await?;
        sqlx::query("INSERT INTO oauth_sessions(incarnation,name,refresh_token_ciphertext,refresh_token_nonce,created_at,updated_at) VALUES(99,'gone',X'05',X'06',12,34)").execute(&mut c).await?;
        sqlx::query("DELETE FROM oauth_sessions WHERE incarnation=99 OR ?=0")
            .bind(keep)
            .execute(&mut c)
            .await?;
        assert!(
            sqlx::query(
                "UPDATE oauth_sessions SET refresh_pending=1 WHERE kind='controlled_linear_v1'"
            )
            .execute(&mut c)
            .await
            .is_err()
                || !keep
        );
        c.close().await?;
        let pool = migrations::open_and_migrate(&path).await?;
        if keep {
            let r = sqlx::query("SELECT * FROM oauth_sessions")
                .fetch_one(&pool)
                .await?;
            assert_eq!(r.get::<Vec<u8>, _>("access_token_ciphertext"), vec![1, 2]);
            assert_eq!(r.get::<Vec<u8>, _>("access_token_nonce"), vec![3, 4]);
            assert_eq!(
                r.get::<Option<Vec<u8>>, _>("refresh_token_ciphertext"),
                None
            );
            assert_eq!(r.get::<Option<i64>, _>("access_token_expires_at"), None);
            assert_eq!(r.get::<i64, _>("token_version"), 8);
            assert_eq!(r.get::<i64, _>("created_at"), 12);
            assert_eq!(r.get::<i64, _>("updated_at"), 34);
            assert_eq!(r.get::<String, _>("owner_id"), "owner");
            sqlx::query("UPDATE oauth_sessions SET refresh_pending=1")
                .execute(&pool)
                .await?;
        }
        let triggers:i64=sqlx::query_scalar("SELECT count(*) FROM sqlite_master WHERE type='trigger' AND name LIKE 'consent_account_%'").fetch_one(&pool).await?;
        assert_eq!(triggers, 3);
        let fresh = OauthSessionRepository::new(pool.clone())
            .create(
                &SealingKey::generate()?,
                "fresh",
                "label",
                "synthetic",
                None,
                None,
                "",
            )
            .await?;
        assert!(fresh.incarnation > 99);
        assert!(matches!(
            old.run(&pool).await,
            Err(sqlx::migrate::MigrateError::VersionMissing(16))
        ));
        pool.close().await;
    }
    Ok(())
}
