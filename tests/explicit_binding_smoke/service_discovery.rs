use super::{Fixture, Value, setup, upstream};

async fn discovery(f: &Fixture, token: &str) -> Value {
    f.http
        .get(f.url("/tools"))
        .bearer_auth(token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

pub(super) async fn verify_scoping(f: &Fixture, agents: &[setup::Agent]) {
    verify_catalogs(f, agents).await;
    let allowed = discovery(f, &agents[0].token).await;
    let other = discovery(f, &agents[1].token).await;
    assert!(allowed.to_string().contains("customer-jobs"));
    assert!(!other.to_string().contains("customer-jobs"));
    let unbound = discovery(f, &agents[3].token).await;
    assert_eq!(unbound["tools"][0]["account_selected"], false);
    assert_eq!(unbound["tools"][0]["credential_readiness"], "not_checked");
    let generic = skill(f, None).await;
    assert!(!generic.contains("customer-jobs") && !generic.contains("check-account"));
    let personal = skill(f, Some(&agents[0].token)).await;
    assert!(personal.contains("http_service") && personal.contains("customer-jobs"));
    for text in [allowed.to_string(), other.to_string(), generic, personal] {
        for private in [
            "private-marker",
            "SMOKE_X",
            "SMOKE_Y",
            upstream::X,
            upstream::Y,
            &f.upstream,
        ] {
            assert!(!text.contains(private));
        }
    }
}

async fn verify_catalogs(f: &Fixture, agents: &[setup::Agent]) {
    for agent in agents {
        let listing = discovery(f, &agent.token).await;
        let personal = skill(f, Some(&agent.token)).await;
        let expected: std::collections::BTreeSet<_> = listing["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| entry["name"].as_str().unwrap())
            .collect();
        assert_eq!(
            table_names(&personal),
            expected,
            "catalog-backed skill/tools agreement"
        );
        assert!(!personal.contains("This document is the **generic** form"));
        for name in expected {
            assert!(!personal.contains(&format!("/api/{name}/v1/chat/completions")));
        }
        for state in ["account_selected", "not_checked", "connection_not_active"] {
            assert!(personal.contains(state));
        }
    }
}

fn table_names(skill: &str) -> std::collections::BTreeSet<&str> {
    let table = skill
        .split_once("### Tools eligible under your ACL\n")
        .unwrap()
        .1;
    table
        .split("\n### ")
        .next()
        .unwrap()
        .lines()
        .filter_map(|line| line.strip_prefix("| `")?.split_once("` |"))
        .map(|(name, _)| name)
        .collect()
}

pub(super) async fn call(f: &Fixture, token: &str, name: &str) -> reqwest::Response {
    let listing = discovery(f, token).await;
    let entry = listing["tools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["name"] == name)
        .unwrap();
    let operation = &entry["http_service"]["operations"][0];
    let response = request(f, token, entry, operation).send().await.unwrap();
    assert_eq!(
        response.status().as_u16(),
        operation["response"]["status"].as_u64().unwrap() as u16
    );
    assert!(
        response.headers()["content-type"]
            .to_str()
            .unwrap()
            .starts_with(operation["response"]["content_type"].as_str().unwrap())
    );
    response
}

fn request(f: &Fixture, token: &str, entry: &Value, operation: &Value) -> reqwest::RequestBuilder {
    let path = format!(
        "{}{}",
        entry["path"].as_str().unwrap(),
        operation["path"].as_str().unwrap()
    );
    let method = operation["method"].as_str().unwrap().parse().unwrap();
    let query: Vec<_> = operation["example"]["query"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(key, value)| (key, value.as_str().unwrap()))
        .collect();
    f.http
        .request(method, f.url(&path))
        .bearer_auth(token)
        .query(&query)
}

async fn skill(f: &Fixture, token: Option<&str>) -> String {
    let mut request = f.http.get(f.url("/skill"));
    if let Some(token) = token {
        request = request.bearer_auth(token);
    }
    request.send().await.unwrap().text().await.unwrap()
}
