use super::consent;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn slack_metadata_actual_status_categories_and_privacy() {
    consent::slack::metadata::categorical().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn slack_metadata_actual_duplicate_depth_and_body_limits() {
    consent::slack::metadata::bounds().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn slack_metadata_refresh_response_is_immediate_and_pending_cannot_retry() {
    consent::slack::metadata_refresh::immediate_reason().await;
}
