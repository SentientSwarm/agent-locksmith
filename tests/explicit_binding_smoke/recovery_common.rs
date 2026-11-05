use super::{fixture::Fixture, migration, oauth_setup, process};
use serde_json::Value;

pub fn bootstrap(f: &Fixture, fresh: &str) -> std::process::Command {
    f.cli(&[
        "oauth",
        "bootstrap",
        "accounts",
        "--label",
        "reader",
        "--refresh-token",
        fresh,
    ])
}
pub fn connect(f: &Fixture, fresh: &str) {
    assert!(process::run(bootstrap(f, fresh)).status.success());
}
pub fn state(f: &Fixture) -> String {
    migration::sqlite(
        f,
        &f.db,
        "SELECT json_array(incarnation, token_version, hex(refresh_token_ciphertext), hex(access_token_ciphertext), access_token_expires_at) FROM oauth_sessions ORDER BY name,session_label;",
    )
}
pub fn expiry(f: &Fixture, value: i64) {
    migration::sqlite(
        f,
        &f.db,
        &format!("UPDATE oauth_sessions SET access_token_expires_at={value};"),
    );
}
pub fn attempt(f: &Fixture, token: &str, bootstrap_attempt: bool) -> tokio::task::JoinHandle<()> {
    if bootstrap_attempt {
        let command = bootstrap(f, "synthetic-first-refresh");
        tokio::task::spawn_blocking(move || {
            let _ = process::run(command);
        })
    } else {
        let request = f.http.get(f.url("/api/accounts/check")).bearer_auth(token);
        tokio::spawn(async move {
            let _ = request.send().await;
        })
    }
}
pub fn pending(f: &Fixture) {
    let status = f.op(&["oauth", "status", "accounts", "--label", "reader"]);
    assert_eq!(status["present"], true);
    assert_eq!(status["refresh_pending"], true);
    assert_eq!(status["reconnect_required"], true);
    let list = f.op(&["oauth", "list"]);
    assert!(list.to_string().contains("refresh_pending"));
}
pub async fn denied(f: &Fixture, token: &str) {
    for _ in 0..3 {
        let response = f
            .http
            .get(f.url("/api/accounts/check"))
            .bearer_auth(token)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 503);
        let json: Value = response.json().await.unwrap();
        assert_eq!(json["error"]["code"], "oauth_reconnect_required");
    }
    assert!(
        !process::run(bootstrap(f, "synthetic-first-refresh"))
            .status
            .success()
    );
    oauth_setup::safe_reads(f);
}
