use super::{fixture::Fixture, process, support};

pub async fn exercise() {
    let prior = std::env::var("LOCKSMITH_DEFINITION_PRIOR_DAEMON")
        .expect("qualified public schema11 1de53fc daemon required");
    let mut f = Fixture::new();
    // The prior binary logs its configured address, so it cannot report an
    // OS-assigned port.
    f.use_stable_port();
    f.start(&prior).await;
    f.enroll("existing", "https://example.com/mcp");
    assert_eq!(version(&f).await, 11);
    let before = support::authority(&f).await;
    f.stop();
    f.start(process::DAEMON).await;
    assert_eq!(version(&f).await, 16);
    assert_eq!(support::authority(&f).await, before);
    no_automatic_definitions(&f).await;
    support::import(&f, 1);
    support::create(&f, "https://example.com/mcp");
    f.stop();
    refused(&f, &prior);
    f.start(process::DAEMON).await;
    assert_eq!(f.op(&["tool", "get", "customer"])["disabled"], true);
    assert_eq!(support::authority(&f).await, before);
    f.stop();
    println!(
        "Actual public1de53fc schema11->16: existing native authority preserved, zero automatic definitions, old binary refuses before listeners, current restart retains disabled pin"
    );
}
async fn version(f: &Fixture) -> i64 {
    let pool = support::pool(f).await;
    let version = sqlx::query_scalar("SELECT max(version) FROM _sqlx_migrations")
        .fetch_one(&pool)
        .await
        .unwrap();
    pool.close().await;
    version
}
fn refused(f: &Fixture, prior: &str) {
    let _ = std::fs::remove_file(f.path().join("admin.sock"));
    let mut command = process::command(prior);
    command.arg("--config").arg(f.path().join("config.yaml"));
    let out = process::run(command);
    assert!(!out.status.success());
    let message = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(message.contains("migration 12") && message.contains("missing"));
    assert!(!f.path().join("admin.sock").exists());
    assert!(std::net::TcpStream::connect(("127.0.0.1", f.port)).is_err());
}

async fn no_automatic_definitions(f: &Fixture) {
    let pool = support::pool(f).await;
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM integration_definitions")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 0);
    pool.close().await;
}
