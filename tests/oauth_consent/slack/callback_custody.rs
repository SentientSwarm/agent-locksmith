use super::{callback_support::*, *};

pub async fn refusals() {
    for mutation in [
        "UPDATE oauth_consent_attempts SET deadline=0",
        "UPDATE oauth_consent_attempts SET profile_digest='changed'",
        "UPDATE oauth_consent_attempts SET config_revision=config_revision+1",
        "UPDATE oauth_consent_attempts SET owner_id='other'",
        "UPDATE oauth_consent_clients SET retired_at=1",
    ] {
        one(mutation).await;
    }
}

async fn one(mutation: &str) {
    eprintln!("custody fixture mutation: {mutation}");
    let (mut f, t) = ready(true).await;
    let attempt = setup::connect_slack(&f, "changed");
    let raw = setup::issue(&f, &attempt, false).await;
    let arrivals = counts(&f);
    let options = sqlx::sqlite::SqliteConnectOptions::new().filename(f.path().join("state.db"));
    let pool = sqlx::SqlitePool::connect_with(options).await.unwrap();
    sqlx::query(mutation).execute(&pool).await.unwrap();
    assert_eq!(send(&f, without_issuer(&raw)).await, 400);
    assert_eq!(
        counts(&f),
        arrivals,
        "preclaim refusal sends no token or identity request"
    );
    absent(&f, &pool, mutation).await;
    pool.close().await;
    f.stop();
    t.stop();
}

pub async fn controlled() {
    let mut f = Fixture::new();
    let t = Twin::start(&f);
    configure(&f, &t);
    start(&mut f).await;
    let port = bound_callback(&f);
    registration(&f, &t, port).await;
    let attempt = connect(&f, "strict");
    let raw = super::super::callback(&t, port, &attempt);
    assert_eq!(send(&f, without_issuer(&raw)).await, 400);
    assert!(!f.path().join("counts.json").exists());
    assert_eq!(send(&f, raw.parse().unwrap()).await, 200);
    f.stop();
    t.stop();
}

async fn absent(f: &Fixture, pool: &sqlx::SqlitePool, mutation: &str) {
    let args = ["oauth", "account-status", "fixture", "--label", "changed"];
    if mutation.contains("owner_id") {
        let result = process::run(f.command(&args));
        assert_eq!(result.status.code(), Some(4));
        assert!(String::from_utf8_lossy(&result.stderr).contains("not_found"));
        eprintln!("foreign-owner account-status: exit4, closed not_found");
    } else {
        assert_eq!(f.op(&args)["state"], "absent");
    }
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM oauth_sessions WHERE name='fixture' AND session_label='changed'",
    )
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(count, 0, "no account published for any stale custody case");
}
