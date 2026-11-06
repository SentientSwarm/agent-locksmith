#![allow(dead_code)] // Shared fixture support also serves the existing native targets.
#[path = "native_oauth/fixture.rs"]
mod controlled;
#[path = "native/fixture.rs"]
mod native;
#[path = "native_process/pki.rs"]
mod pki;
#[path = "native_preparation/support.rs"]
mod support;
use agent_locksmith::{
    native_authority::{effective::Snapshot, store},
    registrations::AuthSpec,
};
use serde_json::json;

#[tokio::test]
async fn selection_requires_owner_revision_acl_and_cannot_use_generic_writer() {
    let s = controlled::setup().await;
    let view =
        s.rt.consent
            .as_ref()
            .unwrap()
            .account("owner", "native", "x")
            .await
            .unwrap();
    let revision = view["revision"].as_str().unwrap();
    assert_eq!(
        s.rt.select_oauth("other", &s.agent, "native", "x", revision)
            .await
            .unwrap_err()
            .0,
        "not_found"
    );
    assert_eq!(
        s.rt.select_oauth("owner", &s.agent, "native", "x", "stale")
            .await
            .unwrap_err()
            .0,
        "source_conflict"
    );
    s.f.agents
        .update_policy(&s.agent, Some(Some(vec![])), None, None, None)
        .await
        .unwrap();
    assert_eq!(
        s.rt.select_oauth("owner", &s.agent, "native", "x", revision)
            .await
            .unwrap_err()
            .0,
        "connection_not_allowed"
    );
    assert!(
        s.f.bindings
            .get(s.f.agent_id, "native")
            .await
            .unwrap()
            .is_none()
    );
    s.f.agents
        .update_policy(
            &s.agent,
            Some(Some(vec!["native".into()])),
            None,
            None,
            None,
        )
        .await
        .unwrap();
    let selected =
        s.rt.select_oauth("owner", &s.agent, "native", "x", revision)
            .await
            .unwrap();
    let auth: AuthSpec = serde_json::from_value(selected["selection"].clone()).unwrap();
    assert!(
        s.f.bindings
            .set(s.f.agent_id, "native", &auth)
            .await
            .is_err()
    );
    assert_eq!(
        s.rt.snapshot_for(Some("other"), &s.agent, "native")
            .await
            .unwrap_err()
            .0,
        "not_found"
    );
    assert_eq!(
        s.rt.snapshot(&s.agent, "native").await.unwrap_err().0,
        "not_found"
    );
    let own =
        s.rt.snapshot_for(Some("owner"), &s.agent, "native")
            .await
            .unwrap();
    assert_eq!(own["effective_tools"], json!([]));
    assert_eq!(own["source"], selected["source"]);
    let mut reg = s.f.repo.get("other").await.unwrap().unwrap();
    reg.auth = auth;
    assert!(s.f.repo.upsert(&reg).await.is_err());
}
#[tokio::test]
async fn refresh_claim_and_version_change_invalidate_source_and_session_without_refresh_material() {
    let s = controlled::setup().await;
    controlled::select(&s).await;
    let before = s.current().await;
    assert!(before.scope().ends_with(&before.source.account_key));
    sqlx::query("UPDATE oauth_sessions SET token_version=token_version+1,refresh_pending=1 WHERE name='native'").execute(&s.f.pool).await.unwrap();
    assert_eq!(
        s.rt.current(&mut s.f.pool.acquire().await.unwrap(), &s.agent, "native")
            .await
            .err()
            .unwrap()
            .0,
        "controlled_account_unavailable"
    );
    sqlx::query("UPDATE oauth_sessions SET token_version=token_version+1,refresh_pending=0 WHERE name='native'").execute(&s.f.pool).await.unwrap();
    let after = s.current().await;
    assert_ne!(before.source.account_key, after.source.account_key);
    assert_ne!(before.scope(), after.scope());
    assert!(after.matches(&before.source).is_err());
    let state =
        s.rt.snapshot_for(Some("owner"), &s.agent, "native")
            .await
            .unwrap();
    assert_eq!(state["effective_tools"], json!([]));
    let missing:bool=sqlx::query_scalar("SELECT refresh_token_ciphertext IS NULL AND access_token_expires_at IS NULL FROM oauth_sessions").fetch_one(&s.f.pool).await.unwrap();
    assert!(missing);
}
#[tokio::test]
async fn disconnect_removes_selection_and_reconnect_never_revives_it() {
    let s = controlled::setup().await;
    controlled::select(&s).await;
    let old = s.current().await.source;
    let rt = s.rt.consent.as_ref().unwrap();
    let v = rt.account("owner", "native", "x").await.unwrap();
    rt.disconnect("owner", "native", "x", v["revision"].as_str().unwrap())
        .await
        .unwrap();
    assert!(
        s.f.bindings
            .get(s.f.agent_id, "native")
            .await
            .unwrap()
            .is_none()
    );
    controlled::insert(
        &s,
        &controlled::profile(s.f._dir.path(), 19293),
        &controlled::key(),
        "x",
        "owner",
    )
    .await;
    assert!(
        s.rt.current(&mut s.f.pool.acquire().await.unwrap(), &s.agent, "native")
            .await
            .is_err()
    );
    controlled::select(&s).await;
    assert_ne!(old, s.current().await.source);
}
#[tokio::test]
async fn expiry_is_checked_again_after_captured_snapshot() {
    let s = controlled::setup().await;
    sqlx::query("UPDATE oauth_sessions SET access_token_expires_at=?")
        .bind(store::now() + 1)
        .execute(&s.f.pool)
        .await
        .unwrap();
    controlled::select(&s).await;
    let current = s.current().await;
    let snap = Snapshot {
        current,
        generation: None,
        revision: None,
        observed_at: Some(store::now()),
        expires_at: None,
        tools: Default::default(),
    };
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    assert_eq!(snap.fresh().unwrap_err().0, "access_expired");
    assert_eq!(
        s.rt.snapshot_for(Some("owner"), &s.agent, "native")
            .await
            .unwrap_err()
            .0,
        "access_expired"
    );
}
#[tokio::test]
async fn loaded_root_bytes_are_frozen_and_next_start_changes_authority() {
    let mut s = controlled::setup().await;
    controlled::select(&s).await;
    let before = s.current().await.source;
    pki::Pki::write(s.f._dir.path());
    assert_eq!(before, s.current().await.source);
    let rt = controlled::runtime(
        &s,
        controlled::profile(s.f._dir.path(), 19293),
        controlled::key(),
    )
    .await;
    s.rt = rt;
    assert_ne!(before.account_key, s.current().await.source.account_key);
}

#[tokio::test]
async fn owner_checks_and_same_stamp_reselection_remove_finite_authority() {
    use agent_locksmith::native_authority::{contract, writes};
    let s = controlled::setup().await;
    controlled::select(&s).await;
    let current = s.current().await;
    let tool = support::tool("read_record");
    let observed = contract::observed(&tool);
    let mut tx = s.f.pool.begin().await.unwrap();
    let generation = store::reserve(&mut tx, &current, &s.rt.run, None)
        .await
        .unwrap();
    store::publish(
        &mut tx,
        &current,
        &generation,
        &json!({"tools":[{"observed_digest":observed,"tool":tool}]}),
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let input = || {
        serde_json::from_value::<writes::Review>(json!({"source":current.source,"generation":generation,"name":"read_record","observed_digest":observed,"effect":"read"})).unwrap()
    };
    assert_eq!(
        s.rt.review_for(Some("other"), &s.agent, "native", input())
            .await
            .unwrap_err()
            .0,
        "not_found"
    );
    assert_eq!(
        s.rt.observe_for(
            Some("other"),
            &s.agent,
            "native",
            &current.source,
            Some(&generation)
        )
        .await
        .unwrap_err()
        .0,
        "not_found"
    );
    let review =
        s.rt.review_for(Some("owner"), &s.agent, "native", input())
            .await
            .unwrap();
    let snapshot =
        s.rt.snapshot_for(Some("owner"), &s.agent, "native")
            .await
            .unwrap();
    let grants = json!([{"name":"read_record","contract_digest":review["contract_digest"]}]);
    assert_eq!(
        s.rt.replace_for(
            Some("other"),
            &s.agent,
            "native",
            support::Setup::replace(&snapshot, grants.clone())
        )
        .await
        .unwrap_err()
        .0,
        "not_found"
    );
    s.rt.replace_for(
        Some("owner"),
        &s.agent,
        "native",
        support::Setup::replace(&snapshot, grants),
    )
    .await
    .unwrap();
    assert_eq!(
        s.rt.snapshot_for(Some("owner"), &s.agent, "native")
            .await
            .unwrap()["effective_tools"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    controlled::select(&s).await;
    let after =
        s.rt.snapshot_for(Some("owner"), &s.agent, "native")
            .await
            .unwrap();
    assert_eq!(after["effective_tools"], json!([]));
    assert_ne!(
        current.source.agent_epoch,
        s.current().await.source.agent_epoch
    );
}

#[tokio::test]
async fn unavailable_or_unreadable_custody_never_falls_back() {
    let mut s = controlled::setup().await;
    controlled::select(&s).await;
    let current = s.current().await;
    // Corruption is after startup validation; metadata selection does not unseal.
    sqlx::query("UPDATE oauth_sessions SET access_token_ciphertext=X'010203'")
        .execute(&s.f.pool)
        .await
        .unwrap();
    assert_eq!(
        s.rt.observe_for(Some("owner"), &s.agent, "native", &current.source, None)
            .await
            .unwrap_err()
            .0,
        "oauth_custody_unavailable"
    );
    s.rt.consent = None;
    assert_eq!(
        s.rt.current(&mut s.f.pool.acquire().await.unwrap(), &s.agent, "native")
            .await
            .err()
            .unwrap()
            .0,
        "oauth_custody_unavailable"
    );
}

#[tokio::test]
async fn migration17_preserves_complete_custody_and_deleted_highwater() {
    use sqlx::{Connection, Row};
    for keep in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("old.db");
        let mut c = sqlx::SqliteConnection::connect_with(
            &sqlx::sqlite::SqliteConnectOptions::new()
                .filename(&path)
                .create_if_missing(true),
        )
        .await
        .unwrap();
        let mut old = sqlx::migrate!();
        old.migrations = old
            .iter()
            .filter(|m| m.version <= 16)
            .cloned()
            .collect::<Vec<_>>()
            .into();
        old.run(&mut c).await.unwrap();
        sqlx::query("INSERT INTO oauth_sessions(incarnation,name,refresh_token_ciphertext,refresh_token_nonce,access_token_ciphertext,access_token_nonce,access_token_expires_at,scope,degraded,created_at,updated_at,token_version,refresh_pending) VALUES(7,'kept',X'0102',X'0304',X'0506',X'0708',123,'scope',1,12,34,5,1),(99,'gone',X'01',X'02',NULL,NULL,NULL,'',0,1,2,0,0)").execute(&mut c).await.unwrap();
        sqlx::query("DELETE FROM oauth_sessions WHERE incarnation=99 OR ?=0")
            .bind(keep)
            .execute(&mut c)
            .await
            .unwrap();
        let before:Vec<String>=sqlx::query_scalar("SELECT json_array(incarnation,name,hex(refresh_token_ciphertext),hex(refresh_token_nonce),hex(access_token_ciphertext),hex(access_token_nonce),access_token_expires_at,scope,degraded,created_at,updated_at,token_version,refresh_pending,kind,owner_id,profile_id,profile_digest,workspace_id,user_id,scope_echoed) FROM oauth_sessions").fetch_all(&mut c).await.unwrap();
        c.close().await.unwrap();
        let pool = agent_locksmith::migrations::open_and_migrate(&path)
            .await
            .unwrap();
        let after:Vec<String>=sqlx::query_scalar("SELECT json_array(incarnation,name,hex(refresh_token_ciphertext),hex(refresh_token_nonce),hex(access_token_ciphertext),hex(access_token_nonce),access_token_expires_at,scope,degraded,created_at,updated_at,token_version,refresh_pending,kind,owner_id,profile_id,profile_digest,workspace_id,user_id,scope_echoed) FROM oauth_sessions").fetch_all(&pool).await.unwrap();
        assert_eq!(before, after);
        let row=sqlx::query("INSERT INTO oauth_sessions(name,refresh_token_ciphertext,refresh_token_nonce,created_at,updated_at) VALUES('fresh',X'01',X'02',1,2) RETURNING incarnation").fetch_one(&pool).await.unwrap();
        assert!(row.get::<i64, _>("incarnation") > 99);
        assert!(matches!(
            old.run(&pool).await,
            Err(sqlx::migrate::MigrateError::VersionMissing(17))
        ));
        pool.close().await;
    }
}
