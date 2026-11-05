//! Own current OAuth operation futures until shutdown has dropped them all.
use std::{
    future::Future,
    sync::{Arc, Mutex},
};
use tokio_util::{sync::CancellationToken, task::TaskTracker};

#[derive(Clone, Default)]
pub struct RefreshOwner {
    inner: Arc<Inner>,
}

#[derive(Default)]
struct Inner {
    closed: Mutex<bool>,
    cancel: CancellationToken,
    tasks: TaskTracker,
}

impl RefreshOwner {
    /// Closing admission and registering a tracked future share one gate.
    pub async fn run<F: Future>(&self, future: F) -> Option<F::Output> {
        let tracked = {
            let closed = self.inner.closed.lock().expect("refresh owner gate");
            if *closed {
                return None;
            }
            self.inner.tasks.track_future(future)
        };
        tokio::select! {
            biased;
            _ = self.inner.cancel.cancelled() => None,
            output = tracked => Some(output),
        }
    }

    /// Signal only; callers inside a scope must never wait for themselves.
    pub fn close(&self) {
        let mut closed = self.inner.closed.lock().expect("refresh owner gate");
        *closed = true;
        self.inner.cancel.cancel();
        self.inner.tasks.close();
    }

    /// Call after close. Completion means owned futures have been dropped;
    /// submitted SQL or remote operations may still finish independently.
    pub async fn wait(&self) {
        self.inner.tasks.wait().await;
    }
}
