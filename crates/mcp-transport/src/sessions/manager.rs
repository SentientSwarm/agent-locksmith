use super::{Error, OwnedTransport, Scoped, stream::SessionStream};
use futures_util::Stream;
use rmcp::{
    model::{ClientJsonRpcMessage, ServerJsonRpcMessage},
    transport::streamable_http_server::session::{ServerSseMessage, SessionId, SessionManager},
};
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

impl<T: Clone + Send + Sync + 'static> SessionManager for Scoped<T> {
    type Error = Error;
    type Transport = OwnedTransport<T>;
    async fn create_session(&self) -> Result<(SessionId, Self::Transport), Error> {
        self.allocate()
    }
    async fn initialize_session(
        &self,
        id: &SessionId,
        message: ClientJsonRpcMessage,
    ) -> Result<ServerJsonRpcMessage, Error> {
        let entry = self.entry(id)?;
        let response = super::operations::run(&entry, entry.handle.initialize(message)).await?;
        Ok(response)
    }
    fn initialization_response(
        &self,
        id: &SessionId,
        response: ServerJsonRpcMessage,
    ) -> Result<impl Stream<Item = ServerSseMessage> + Send + Sync + 'static, Error> {
        let entry = self.entry(id)?;
        super::operations::charge(&entry, true, false)?;
        Ok(SessionStream::lease(entry, false).initial(ServerSseMessage::from_message(response)))
    }
    async fn has_session(&self, id: &SessionId) -> Result<bool, Error> {
        Ok(self.entry(id).is_ok())
    }
    async fn close_session(&self, id: &SessionId) -> Result<(), Error> {
        self.retire(id);
        Ok(())
    }
    async fn create_stream(
        &self,
        id: &SessionId,
        message: ClientJsonRpcMessage,
    ) -> Result<impl Stream<Item = ServerSseMessage> + Send + Sync + 'static, Error> {
        self.request_stream(id, message).await
    }
    async fn accept_message(
        &self,
        id: &SessionId,
        message: ClientJsonRpcMessage,
    ) -> Result<(), Error> {
        let entry = self.entry(id)?;
        super::operations::charge(&entry, false, false)?;
        super::operations::run(&entry, entry.handle.push_message(message, None)).await
    }
    async fn create_standalone_stream(
        &self,
        id: &SessionId,
    ) -> Result<impl Stream<Item = ServerSseMessage> + Send + Sync + 'static, Error> {
        let entry = self.entry(id)?;
        super::operations::charge(&entry, true, true)?;
        let lease = SessionStream::lease(entry.clone(), true);
        let receiver =
            super::operations::run(&entry, entry.handle.establish_common_channel()).await?;
        Ok(lease.attach(receiver.inner))
    }
    async fn resume(
        &self,
        _id: &SessionId,
        _last: String,
    ) -> Result<impl Stream<Item = ServerSseMessage> + Send + Sync + 'static, Error> {
        Err::<SessionStream<T>, _>(Error::Resume)
    }
    fn session_initialized(&self, id: &SessionId) {
        if let Ok(entry) = self.entry(id) {
            entry.initialized.cancel();
        }
    }
    fn session_cancellation_token(&self, id: &SessionId) -> CancellationToken {
        self.cancellation(id).unwrap_or_else(|_| {
            let ct = CancellationToken::new();
            ct.cancel();
            ct
        })
    }
    fn spawn_session(&self, id: SessionId, future: impl Future<Output = bool> + Send + 'static) {
        let entry = self.pool.0.state.lock().unwrap().entries.get(&id).cloned();
        if let Some(entry) = entry {
            own_service(entry, future);
        }
    }
}
fn own_service<T: Send + Sync + 'static>(
    entry: Arc<super::entry::Entry<T>>,
    future: impl Future<Output = bool> + Send + 'static,
) {
    entry.state.lock().unwrap().outer_started = true;
    if let Some(pool) = entry.pool.upgrade() {
        pool.state.lock().unwrap().metrics.services_created += 1;
    }
    let task = tokio::spawn(future);
    tokio::spawn(async move {
        // Never abort this join owner. Unexpected task panic leaves capacity
        // charged: it cannot establish that nested SDK shutdown completed.
        let completed = matches!(task.await, Ok(true));
        entry.retire();
        if completed {
            entry.complete(false);
        }
    });
}
