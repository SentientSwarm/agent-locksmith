use super::{Error, entry::Entry};
use rmcp::{
    RoleServer,
    model::{ClientJsonRpcMessage, ServerJsonRpcMessage},
    transport::{
        Transport, WorkerTransport, streamable_http_server::session::local::LocalSessionWorker,
    },
};
use std::sync::Arc;

/// Close/drop transfers worker join custody to cleanup independent of the caller.
pub struct OwnedTransport<T: Send + Sync + 'static> {
    inner: Option<WorkerTransport<LocalSessionWorker>>,
    entry: Arc<Entry<T>>,
}
impl<T: Send + Sync + 'static> OwnedTransport<T> {
    pub(crate) fn new(inner: WorkerTransport<LocalSessionWorker>, entry: Arc<Entry<T>>) -> Self {
        Self {
            inner: Some(inner),
            entry,
        }
    }
    fn cleanup(&mut self) {
        self.entry.retire();
        if let Some(mut worker) = self.inner.take() {
            let entry = self.entry.clone();
            tokio::spawn(async move {
                // This future is never timeout-dropped. The watchdog may abort
                // the SDK worker, but close still awaits that SAME join handle.
                let _ = worker.close().await;
                entry.complete(true);
            });
        }
    }
}
impl<T: Send + Sync + 'static> Transport<RoleServer> for OwnedTransport<T> {
    type Error = Error;
    fn send(
        &mut self,
        message: ServerJsonRpcMessage,
    ) -> impl Future<Output = Result<(), Error>> + Send + 'static {
        let sending = self.inner.as_mut().map(|worker| worker.send(message));
        let closed = self.entry.closed.clone();
        async move {
            let Some(sending) = sending else {
                return Err(Error::Unavailable);
            };
            tokio::select! {
                _ = closed.cancelled() => Err(Error::Unavailable),
                result = sending => result.map_err(|_| Error::Transport),
            }
        }
    }
    async fn receive(&mut self) -> Option<ClientJsonRpcMessage> {
        let worker = self.inner.as_mut()?;
        tokio::select! {
            _ = self.entry.closed.cancelled() => None,
            message = worker.receive() => message,
        }
    }
    async fn close(&mut self) -> Result<(), Error> {
        self.cleanup();
        self.entry.worker_done.cancelled().await;
        Ok(())
    }
}
impl<T: Send + Sync + 'static> Drop for OwnedTransport<T> {
    fn drop(&mut self) {
        self.cleanup();
    }
}
