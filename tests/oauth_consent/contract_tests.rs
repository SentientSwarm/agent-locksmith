use super::consent;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn declared_contract_user() {
    consent::contract::journey(false, false, false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn declared_contract_principal_none() {
    consent::contract::journey(true, false, false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn declared_contract_slack_root() {
    consent::contract::journey(false, true, false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn declared_contract_slack_nested() {
    consent::contract::journey(false, true, true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn declared_contract_missing_scope_refresh_identity_and_retired_client() {
    consent::contract::denials::run().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn declared_contract_identity_diagnostics() {
    consent::contract::identity::run().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn declared_contract_token_refusal_and_challenge() {
    consent::contract::capability::run().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn declared_contract_lifecycle_user() {
    consent::contract::lifecycle::run(false).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn declared_contract_lifecycle_principal() {
    consent::contract::lifecycle::run(true).await;
}
