//! Diagnostic executable, not a production feature or an expected-failure test.
//! Run with synthetic environment values as documented in the proof report.
//! Exit 1 means at least one proposed safe contract is violated by this baseline.
mod access;
mod application;
mod fixture;
mod oauth;

use fixture::{Fixture, env_auth};
use serde_json::{Value, json};

fn record(rows: &mut Vec<Value>, name: &str, actual: Value, expected: Value) {
    rows.push(
        json!({ "case": name, "safe_contract_met": actual == expected,
        "expected": expected, "actual": actual }),
    );
}

fn denied(status: u16) -> Value {
    json!({"status": status, "upstream_calls": 0, "account": null})
}

fn forwarded(account: &str) -> Value {
    json!({"status": 200, "upstream_calls": 1, "account": account})
}

fn check_environment() {
    assert_eq!(
        std::env::var("LOCKSMITH_LOCAL_PROOF_SELECTED").as_deref(),
        Ok("proof-selected")
    );
    assert_eq!(
        std::env::var("LOCKSMITH_LOCAL_PROOF_EMPTY").as_deref(),
        Ok("")
    );
    assert!(std::env::var_os("LOCKSMITH_LOCAL_PROOF_MISSING").is_none());
}

fn env_inputs() -> [(&'static str, &'static str, Value); 3] {
    [
        (
            "valid override",
            "LOCKSMITH_LOCAL_PROOF_SELECTED",
            forwarded("selected"),
        ),
        (
            "missing override",
            "LOCKSMITH_LOCAL_PROOF_MISSING",
            denied(503),
        ),
        ("empty override", "LOCKSMITH_LOCAL_PROOF_EMPTY", denied(503)),
    ]
}

async fn env_cases(rows: &mut Vec<Value>, is_header: bool) {
    let h = Fixture::new(is_header, false).await;
    let mode = if is_header { "header" } else { "bearer" };
    record(
        rows,
        &format!("{mode}: no override"),
        h.request("proof").await,
        denied(403),
    );
    for (label, variable, expected) in env_inputs() {
        h.store
            .overrides
            .set(h.agent_id, "proof", &env_auth(is_header, variable))
            .await
            .unwrap();
        record(
            rows,
            &format!("{mode}: {label}"),
            h.request("proof").await,
            expected,
        );
    }
}

async fn store_failure(rows: &mut Vec<Value>) {
    let h = Fixture::new(false, false).await;
    h.store
        .overrides
        .set(
            h.agent_id,
            "proof",
            &env_auth(false, "LOCKSMITH_LOCAL_PROOF_SELECTED"),
        )
        .await
        .unwrap();
    record(
        rows,
        "before override-store fault",
        h.request("proof").await,
        forwarded("selected"),
    );
    sqlx::query("DROP TABLE agent_credential_overrides")
        .execute(&h.store.pool)
        .await
        .unwrap();
    record(
        rows,
        "override-store failure",
        h.request("proof").await,
        denied(503),
    );
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    check_environment();
    let mut rows = Vec::new();
    env_cases(&mut rows, false).await;
    env_cases(&mut rows, true).await;
    store_failure(&mut rows).await;
    access::run(&mut rows).await;
    oauth::run(&mut rows).await;
    let failures = rows
        .iter()
        .filter(|r| r["safe_contract_met"] == false)
        .count();
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "version": env!("CARGO_PKG_VERSION"), "cases": rows,
            "safe_contract_failures": failures,
            "scope": "real proxy and SQLite; local synthetic upstream accounts"
        }))
        .unwrap()
    );
    if failures > 0 {
        std::process::exit(1);
    }
}
