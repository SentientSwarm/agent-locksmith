use super::consent;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn callback_issuer_slack_dedicated_positive_and_wrong_verifier() {
    consent::slack::callback::positive().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn callback_issuer_slack_dedicated_refusals_preserve_state() {
    consent::slack::callback::adversarial().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn callback_issuer_slack_legacy_still_requires_issuer() {
    consent::slack::callback::legacy().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn callback_issuer_slack_changed_custody_never_exchanges() {
    consent::slack::callback_custody::refusals().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn callback_issuer_controlled_requires_exact_issuer() {
    consent::slack::callback_custody::controlled().await;
}
