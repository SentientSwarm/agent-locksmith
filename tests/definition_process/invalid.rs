use super::{fixture::Fixture, support};
use serde_json::{Value, json};
const PATH: &str = "/admin/operator/integration-definitions/local.customer/revisions/1";

pub async fn exercise(f: &Fixture, agent: &str) {
    malformed(f).await;
    let mut d: Value =
        serde_json::from_slice(&std::fs::read(support::document(f, 1)).unwrap()).unwrap();
    let (status, _) = support::raw(f, agent, PATH, d.to_string().into_bytes()).await;
    assert_eq!(status, 401);
    d["summary"] = json!("conflict");
    let (status, _) = support::raw(f, &f.operator, PATH, d.to_string().into_bytes()).await;
    assert_eq!(status, 409);
    legacy(f);
    let pool = support::pool(f).await;
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM integration_definitions")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 2);
    pool.close().await;
}

async fn malformed(f: &Fixture) {
    let duplicate = br#"{"id":"definition-secret-canary","\u0069d":"local.customer"}"#.to_vec();
    let file = f.path().join("duplicate.json");
    std::fs::write(&file, &duplicate).unwrap();
    support::refused_cli(
        f,
        &["integration", "import", "--file", file.to_str().unwrap()],
        2,
    );
    for bytes in [
        duplicate,
        vec![b' '; 65537],
        b"[]".to_vec(),
        br#"{"unknown":"definition-secret-canary"}"#.to_vec(),
    ] {
        let (status, body) = support::raw(f, &f.operator, PATH, bytes).await;
        assert_eq!(status, 400);
        assert!(!String::from_utf8_lossy(&body).contains("definition-secret-canary"));
    }
}

fn legacy(f: &Fixture) {
    support::refused_cli(f, &["tool", "enable", "customer"], 5);
    support::refused_cli(
        f,
        &[
            "tool",
            "put",
            "customer",
            "--upstream",
            "https://example.com",
            "--auth",
            "none",
        ],
        5,
    );
    support::refused_cli(
        f,
        &["integration", "get", "local.customer", "--revision", "3"],
        4,
    );
}
