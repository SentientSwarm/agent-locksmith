//! Consumer commands against the shipped reference and an independently configured API.
use super::{docs, fixture::Fixture, process, setup, upstream};
use std::{process::Stdio, time::Duration};
use wiremock::{Mock, MockServer, ResponseTemplate, matchers::any};

pub async fn exercise() {
    let output = tempfile::NamedTempFile::new().unwrap();
    let mut command = docs::command(docs::SETUP, "reference");
    command
        .env("REPO_ROOT", env!("CARGO_MANIFEST_DIR"))
        .env("REFERENCE_PORT", "0");
    command.stdout(Stdio::from(output.reopen().unwrap()));
    command.stderr(Stdio::null());
    let reference = process::Guard(command.spawn().unwrap());
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let url = loop {
        let url = std::fs::read_to_string(output.path()).unwrap();
        if !url.trim().is_empty() {
            break url.trim().to_owned();
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "reference API startup deadline (requires Python 3)"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    let mut f = Fixture::new(&url);
    f.start().await;
    let agents = setup::enroll(&f).await;
    for (a, account) in agents[..3].iter().zip(["X", "X", "Y"]) {
        let response = upstream::call(&f, Some(&a.token), "accounts/check").await;
        assert_eq!(response.status(), 200);
        assert_eq!(response.text().await.unwrap(), account);
    }
    let before: serde_json::Value = f
        .http
        .get(format!("{url}/counts"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        before,
        serde_json::json!({"received":3,"X":2,"Y":1,"NONE":0})
    );
    assert_eq!(
        upstream::call(&f, Some(&agents[3].token), "accounts/check")
            .await
            .status(),
        403
    );
    let after: serde_json::Value = f
        .http
        .get(format!("{url}/counts"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(after, before);

    let customer = MockServer::start().await;
    Mock::given(any())
        .respond_with(|req: &wiremock::Request| {
            assert!(req.url.path().starts_with("/v2/jobs"));
            assert_eq!(req.headers.get("x-customer-key").unwrap(), upstream::Y);
            assert!(!req.headers.contains_key("authorization"));
            assert!(!req.headers.contains_key("x-api-key"));
            let response = ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"account":"customer-beta", "jobs":["demo-job"]}));
            if req.url.path().ends_with("/slow") {
                response.set_delay(Duration::from_secs(2))
            } else {
                response
            }
        })
        .mount(&customer)
        .await;
    for block in ["customer-catalog", "customer-bind"] {
        let mut c = docs::fixture(&f, docs::SETUP, block);
        c.env("CUSTOMER_URL", customer.uri())
            .env("AGENT_ID", &agents[0].id);
        process::json(process::run(c));
    }
    assert_eq!(
        upstream::call(&f, Some(&agents[0].token), "customer-jobs/v2/jobs")
            .await
            .status(),
        403
    );
    assert!(customer.received_requests().await.unwrap().is_empty());
    let audit = f.op(&[
        "audit",
        "query",
        "--agent",
        &agents[0].id,
        "--tool",
        "customer-jobs",
    ]);
    assert!(audit.to_string().contains("not_in_allowlist"));
    let generic = f
        .http
        .get(f.url("/skill"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(!generic.contains("customer-jobs"));
    let mut c = docs::fixture(&f, docs::SETUP, "customer-grant");
    c.env("AGENT_ID", &agents[0].id);
    assert!(process::run(c).status.success(), "documented grant command");
    let personal = f
        .http
        .get(f.url("/skill"))
        .bearer_auth(&agents[0].token)
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(personal.contains("customer-jobs"));
    let mut c = docs::fixture(&f, docs::SETUP, "customer-call");
    c.env("LOCKSMITH_URL", f.url(""))
        .env("LOCKSMITH_AGENT_TOKEN", &agents[0].token);
    assert_eq!(process::json(process::run(c))["account"], "customer-beta");
    assert_eq!(customer.received_requests().await.unwrap().len(), 1);

    // Observe dispatch before revocation: admitted work may finish, next work cannot dispatch.
    let client = f.http.clone();
    let slow_url = f.url("/api/customer-jobs/v2/jobs/slow");
    let token = agents[0].token.clone();
    let admitted = tokio::spawn(async move {
        client
            .get(slow_url)
            .bearer_auth(token)
            .send()
            .await
            .unwrap()
    });
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    while customer.received_requests().await.unwrap().len() != 2 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "customer dispatch deadline"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(!admitted.is_finished(), "delayed operation still in flight");
    f.op(&["agent", "unset-credential", &agents[0].id, "customer-jobs"]);
    let denied = upstream::call(&f, Some(&agents[0].token), "customer-jobs/v2/jobs").await;
    assert_eq!(denied.status(), 403);
    assert_eq!(customer.received_requests().await.unwrap().len(), 2);
    let completed = admitted.await.unwrap();
    assert_eq!(completed.status(), 200);
    assert_eq!(
        completed.json::<serde_json::Value>().await.unwrap()["account"],
        "customer-beta"
    );
    println!(
        "D4 reference Python API X/X/Y, unbound zero arrivals; independent customer header/path, skill/audit denial repair, customer-beta attribution; admitted request completes, next cleared admission zero-dispatch"
    );
    super::safety::verify(&f, &agents).await;
    f.cleanup();
    drop(reference);
    upstream::closed(url.trim_start_matches("http://").parse().unwrap()).await;
}
