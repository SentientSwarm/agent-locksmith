//! Own buffering and its later operation without merging their separate budgets.
use super::{Error, Result};
use crate::oauth::refresh::RefreshOwner;
use serde_json::Value;

pub(super) async fn run<F: std::future::Future<Output = Result<Value>>>(
    owner: &RefreshOwner,
    future: F,
) -> Result<Value> {
    owner.run(future).await.ok_or(Error("shutting_down"))?
}

#[cfg(test)]
#[path = "body_scope/tests.rs"]
mod tests;
