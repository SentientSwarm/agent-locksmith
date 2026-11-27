//! AGENT-378: an agent's own request refreshes a stale observation, once.
use super::{calls, commit, discovery, fixture::Fixture, flow, process, receiver, wire};
use serde_json::{Value, json};

fn behavior(f: &Fixture, value: Value) {
    std::fs::write(f.path().join("behavior.json"), value.to_string()).unwrap();
}
fn counts(f: &Fixture) -> Value {
    serde_json::from_slice(&std::fs::read(f.path().join("counts.json")).unwrap()).unwrap()
}
fn count(f: &Fixture, method: &str) -> i64 {
    counts(f)[method].as_i64().unwrap_or(0)
}
fn log_lines(f: &Fixture, event: &str) -> Vec<String> {
    std::fs::read_to_string(f.path().join("daemon.log"))
        .unwrap()
        .lines()
        .filter(|l| l.contains(event))
        .map(str::to_owned)
        .collect()
}
async fn age(pool: &sqlx::SqlitePool, seconds: i64) {
    sqlx::query("UPDATE native_observations SET observed_at=strftime('%s','now')-?")
        .bind(seconds)
        .execute(pool)
        .await
        .unwrap();
}
fn generation(f: &Fixture, a: &Value) -> Value {
    flow::show(f, a["public_id"].as_str().unwrap())["observation"]["generation"].clone()
}
async fn observed_at(pool: &sqlx::SqlitePool) -> i64 {
    sqlx::query_scalar("SELECT observed_at FROM native_observations")
        .fetch_one(pool)
        .await
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stale_observation_is_refreshed_for_the_call() {
    let (mut f, receiver, a, session, pool) = commit::setup().await;
    let before = generation(&f, &a);
    let lists = count(&f, "tools/list");
    age(&pool, 55).await;
    let r = calls::call(&f, &a, &session, 2, json!({})).await;
    assert!(r["result"].is_object(), "{r}");
    assert_eq!(count(&f, "tools/list"), lists + 1);
    assert_eq!(generation(&f, &a), before);
    let lines = log_lines(&f, "native_observation_refreshed");
    assert!(
        lines
            .iter()
            .any(|l| l.contains("\"outcome\":\"unchanged\"")),
        "{lines:?}"
    );
    pool.close().await;
    f.stop();
    receiver.stop();
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stale_observation_is_refreshed_for_tools_list() {
    let (mut f, receiver, a, session, pool) = commit::setup().await;
    let lists = count(&f, "tools/list");
    age(&pool, 55).await;
    let r = discovery::list(&f, a["token"].as_str().unwrap(), &session, 3).await;
    assert_eq!(r["result"]["tools"][0]["name"], "read_record", "{r}");
    assert_eq!(count(&f, "tools/list"), lists + 1);
    pool.close().await;
    f.stop();
    receiver.stop();
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_changed_tool_loses_its_grant_on_refresh() {
    let (mut f, receiver, a, session, pool) = commit::setup().await;
    let id = a["public_id"].as_str().unwrap();
    let before = generation(&f, &a);
    let mut changed = flow::show(&f, id)["observation"]["manifest"]["tools"][0]["tool"].clone();
    changed["description"] = "A changed description".into();
    std::fs::write(
        f.path().join("manifest.json"),
        json!({"tools":[changed]}).to_string(),
    )
    .unwrap();
    age(&pool, 55).await;
    let r = calls::call(&f, &a, &session, 2, json!({})).await;
    let code = r["error"]["data"]["code"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    assert!(
        ["tool_not_approved", "review_invalid"].contains(&code.as_str()),
        "{r}"
    );
    assert_ne!(generation(&f, &a), before);
    let lines = log_lines(&f, "native_observation_refreshed");
    assert!(
        lines
            .iter()
            .any(|l| l.contains("\"outcome\":\"changed\"") && l.contains("\"invalidated\":1")),
        "{lines:?}"
    );
    assert!(calls::effects(&f).is_empty());
    pool.close().await;
    f.stop();
    receiver.stop();
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_upstream_failure_leaves_the_row_and_backs_off() {
    let (mut f, receiver, a, session, pool) = commit::setup().await;
    behavior(&f, json!({"refuse":{"status":503}}));
    // Past the window, so the call has nothing to fall back on.
    age(&pool, 65).await;
    let stale = observed_at(&pool).await;
    let initializes = count(&f, "initialize");
    let r = calls::call(&f, &a, &session, 2, json!({})).await;
    assert_eq!(r["error"]["data"]["code"], "observation_required", "{r}");
    assert_eq!(count(&f, "initialize"), initializes + 1);
    let r = calls::call(&f, &a, &session, 3, json!({})).await;
    assert_eq!(r["error"]["data"]["code"], "observation_required", "{r}");
    assert_eq!(count(&f, "initialize"), initializes + 1, "backoff");
    assert_eq!(observed_at(&pool).await, stale);
    assert!(!log_lines(&f, "native_observation_refresh_failed").is_empty());
    assert!(calls::effects(&f).is_empty());
    pool.close().await;
    f.stop();
    receiver.stop();
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_calls_refresh_once() {
    let (mut f, receiver, a, session, pool) = commit::setup().await;
    let lists = count(&f, "tools/list");
    behavior(&f, json!({"hold":"tools-list"}));
    age(&pool, 55).await;
    let release = async {
        commit::arrived(&f, "tools-list").await;
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        behavior(&f, json!({}));
        std::fs::write(f.path().join("release-tools-list.json"), "go").unwrap();
    };
    let (r2, r3, r4, ()) = tokio::join!(
        calls::call(&f, &a, &session, 2, json!({})),
        calls::call(&f, &a, &session, 3, json!({})),
        calls::call(&f, &a, &session, 4, json!({})),
        release
    );
    for r in [&r2, &r3, &r4] {
        assert!(r["result"].is_object(), "{r}");
    }
    assert_eq!(count(&f, "tools/list"), lists + 1);
    pool.close().await;
    f.stop();
    receiver.stop();
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_agent_without_grants_triggers_no_refresh() {
    let (mut f, receiver, _a, _session, pool) = commit::setup().await;
    let b = f.op(&[
        "agent",
        "register",
        "--name",
        "ungranted",
        "--allowlist",
        "native",
    ]);
    let id = b["public_id"].as_str().unwrap();
    f.op(&["agent", "set-credential", id, "native", "--no-auth"]);
    let token = b["token"].as_str().unwrap();
    let session = wire::open(&f, token).await;
    age(&pool, 55).await;
    let before = counts(&f);
    discovery::list(&f, token, &session, 2).await;
    assert_eq!(counts(&f), before);
    pool.close().await;
    f.stop();
    receiver.stop();
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_restart_is_refreshed_by_the_new_run() {
    let (mut f, receiver, a, _session, pool) = commit::setup().await;
    let before = generation(&f, &a);
    pool.close().await;
    f.stop();
    f.start(process::DAEMON).await;
    let token = a["token"].as_str().unwrap();
    let session = wire::open(&f, token).await;
    let r = discovery::list(&f, token, &session, 1).await;
    assert_eq!(r["result"]["tools"][0]["name"], "read_record", "{r}");
    let r = calls::call(&f, &a, &session, 2, json!({})).await;
    assert!(r["result"].is_object(), "{r}");
    assert_eq!(generation(&f, &a), before);
    f.stop();
    receiver.stop();
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn secrets_stay_out_of_refresh_logs() {
    let mut f = Fixture::new();
    receiver::configure(&f);
    let upstream = receiver::Receiver::start(&f);
    f.start_with_key(
        process::DAEMON,
        Some("AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="),
    )
    .await;
    let a = f.enroll(
        "sealed",
        &format!("https://localhost:{}/mcp", upstream.port),
    );
    let id = a["public_id"].as_str().unwrap();
    let secret = "fixture-account-x";
    calls::stored(&f, id, secret);
    discovery::grant(&f, id);
    let token = a["token"].as_str().unwrap();
    let session = wire::open(&f, token).await;
    discovery::list(&f, token, &session, 1).await;
    let options = sqlx::sqlite::SqliteConnectOptions::new().filename(f.path().join("state.db"));
    let pool = sqlx::SqlitePool::connect_with(options).await.unwrap();
    age(&pool, 55).await;
    let r = calls::call(&f, &a, &session, 2, json!({})).await;
    assert!(r["result"].is_object(), "{r}");
    let log = std::fs::read_to_string(f.path().join("daemon.log")).unwrap();
    assert!(log.contains("native_observation_refreshed"));
    assert!(!log.contains(secret));
    pool.close().await;
    f.stop();
    upstream.stop();
}
