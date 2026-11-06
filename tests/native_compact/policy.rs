use super::*;
#[path = "policy/cases.rs"]
mod cases;
#[path = "policy/catalog.rs"]
mod catalog;
#[path = "policy/facades.rs"]
mod facades;
#[path = "policy/journey.rs"]
mod journey;
#[path = "policy/prior.rs"]
mod prior;
#[path = "policy/review.rs"]
mod review;
#[path = "policy/support.rs"]
mod support;
use facades::{compact, standard};
use review::grant_policy;
use support::{config, effects, omitted, parse, put, tools, write};
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn finite_v2_customer_none_both_facades() {
    journey::run(false).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn finite_v2_customer_bearer_both_facades() {
    journey::run(true).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires an actual retained schema-19 daemon in LOCKSMITH_CONTRACT_PRIOR_DAEMON"]
async fn finite_v2_actual_old_reader_refuses_and_current_reopens() {
    prior::run().await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn finite_v2_selected_catalog_requires_complete_scan_before_authority() {
    catalog::run().await;
}
