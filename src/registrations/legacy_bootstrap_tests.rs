//! AGENT-299 — legacy `tools` credentials are migrated as written.

use super::bootstrap_from_config_tools;
use crate::config::parse_config_str;
use crate::registrations::{AuthSpec, RegistrationRepository};

/// Migrate one tool whose `auth` block is `auth` (YAML, indented under
/// the tool); the registration's auth, or `None` when it was skipped.
async fn migrate(auth: &str) -> Option<AuthSpec> {
    let yaml = format!(
        "listen:\n  host: \"127.0.0.1\"\n  port: 9200\ntools:\n  - name: \"t\"\n    description: \"d\"\n    upstream: \"https://example.invalid\"\n    auth:\n{auth}\n"
    );
    let config = parse_config_str(&yaml).unwrap();
    let dir = tempfile::TempDir::new().unwrap();
    let pool = crate::migrations::open_and_migrate(&dir.path().join("l.db"))
        .await
        .unwrap();
    let repo = RegistrationRepository::new(pool);
    let (inserted, _, skipped) = bootstrap_from_config_tools(&repo, &config).await.unwrap();
    assert_eq!(inserted + skipped, 1);
    repo.get("t").await.unwrap().map(|r| r.auth)
}

fn bearer(var: &str) -> Option<AuthSpec> {
    Some(AuthSpec::Bearer {
        env_var: var.into(),
    })
}

fn header(name: &str, var: &str) -> Option<AuthSpec> {
    Some(AuthSpec::Header {
        header: name.into(),
        env_var: var.into(),
    })
}

#[tokio::test]
async fn bearer_text_becomes_a_bearer_credential() {
    // The variable holds the token; the text supplied `Bearer `.
    let got =
        migrate("      header: \"Authorization\"\n      value: \"Bearer ${AGENT299_TOKEN}\"").await;
    assert_eq!(got, bearer("AGENT299_TOKEN"));
}

#[tokio::test]
async fn a_bare_variable_text_becomes_a_header_credential() {
    let got = migrate("      header: \"X-Api-Key\"\n      value: \"${AGENT299_KEY}\"").await;
    assert_eq!(got, header("X-Api-Key", "AGENT299_KEY"));
}

#[tokio::test]
async fn from_env_without_a_prefix_stays_a_header_credential() {
    let got =
        migrate("      header: \"Authorization\"\n      value: { from_env: { var: AGENT299_V } }")
            .await;
    assert_eq!(got, header("Authorization", "AGENT299_V"));
}

#[tokio::test]
async fn from_env_with_a_bearer_prefix_becomes_a_bearer_credential() {
    let got = migrate(
        "      header: \"Authorization\"\n      value: { from_env: { var: AGENT299_V, prefix: \"Bearer \" } }",
    )
    .await;
    assert_eq!(got, bearer("AGENT299_V"));
}

#[tokio::test]
async fn a_prefix_no_registration_can_carry_is_not_migrated() {
    for auth in [
        "      header: \"Authorization\"\n      value: { from_env: { var: AGENT299_V, prefix: \"token \" } }",
        "      header: \"Authorization\"\n      value: \"token ${AGENT299_V}\"",
        "      header: \"X-Api-Key\"\n      value: { from_env: { var: AGENT299_V, prefix: \"Bearer \" } }",
        "      header: \"X-Api-Key\"\n      value: \"Bearer ${AGENT299_V}\"",
    ] {
        assert_eq!(migrate(auth).await, None, "{auth}");
    }
}

#[tokio::test]
async fn the_authorization_header_matches_in_any_case() {
    let got =
        migrate("      header: \"authorization\"\n      value: \"Bearer ${AGENT299_TOKEN}\"").await;
    assert_eq!(got, bearer("AGENT299_TOKEN"));
}

#[tokio::test]
async fn text_is_not_migrated_when_the_file_cannot_be_read_as_written() {
    // `{` may not appear in a flow-context plain scalar, so the file
    // parses only after `${VAR}` expansion: the written text is unknown.
    let got = migrate(
        "      header: \"X-Api-Key\"\n      value: \"${AGENT299_KEY}\"\n    timeouts: { request_seconds: 30${AGENT299_UNSET} }",
    )
    .await;
    assert_eq!(got, None);
}
