//! Keep typed capacity errors through the SDK's generic HTTP error renderer.
use super::context::Context;
use futures_util::Stream;
use locksmith_mcp_transport::sessions::{Error, OwnedTransport, Scoped};
use rmcp::{
    model::{ClientJsonRpcMessage, ServerJsonRpcMessage},
    transport::streamable_http_server::session::{ServerSseMessage, SessionId, SessionManager},
};
use std::sync::{
    Arc,
    atomic::{AtomicU16, Ordering},
};
use tokio_util::sync::CancellationToken;

pub(super) struct Manager {
    pub inner: Scoped<Arc<Context>>,
    pub status: Arc<AtomicU16>,
}
impl Manager {
    fn record<T>(&self, value: Result<T, Error>) -> Result<T, Error> {
        if let Err(error) = &value {
            self.status.store(
                match error {
                    Error::Capacity | Error::Limit => 429,
                    Error::Unavailable => 404,
                    Error::Resume => 400,
                    Error::Transport => 503,
                    Error::Config => 500,
                },
                Ordering::SeqCst,
            );
        }
        value
    }
}
impl SessionManager for Manager {
    type Error = Error;
    type Transport = OwnedTransport<Arc<Context>>;
    async fn create_session(&self) -> Result<(SessionId, Self::Transport), Error> {
        self.record(self.inner.create_session().await)
    }
    async fn initialize_session(
        &self,
        id: &SessionId,
        message: ClientJsonRpcMessage,
    ) -> Result<ServerJsonRpcMessage, Error> {
        self.record(self.inner.initialize_session(id, message).await)
    }
    fn initialization_response(
        &self,
        id: &SessionId,
        response: ServerJsonRpcMessage,
    ) -> Result<impl Stream<Item = ServerSseMessage> + Send + Sync + 'static, Error> {
        self.record(self.inner.initialization_response(id, response))
    }
    async fn has_session(&self, id: &SessionId) -> Result<bool, Error> {
        self.record(self.inner.has_session(id).await)
    }
    async fn close_session(&self, id: &SessionId) -> Result<(), Error> {
        self.record(self.inner.close_session(id).await)
    }
    async fn create_stream(
        &self,
        id: &SessionId,
        message: ClientJsonRpcMessage,
    ) -> Result<impl Stream<Item = ServerSseMessage> + Send + Sync + 'static, Error> {
        self.record(self.inner.create_stream(id, message).await)
    }
    async fn accept_message(
        &self,
        id: &SessionId,
        message: ClientJsonRpcMessage,
    ) -> Result<(), Error> {
        self.record(self.inner.accept_message(id, message).await)
    }
    async fn create_standalone_stream(
        &self,
        id: &SessionId,
    ) -> Result<impl Stream<Item = ServerSseMessage> + Send + Sync + 'static, Error> {
        self.record(self.inner.create_standalone_stream(id).await)
    }
    async fn resume(
        &self,
        id: &SessionId,
        last: String,
    ) -> Result<impl Stream<Item = ServerSseMessage> + Send + Sync + 'static, Error> {
        self.record(self.inner.resume(id, last).await)
    }
    fn session_initialized(&self, id: &SessionId) {
        self.inner.session_initialized(id);
    }
    fn session_cancellation_token(&self, id: &SessionId) -> CancellationToken {
        self.inner.session_cancellation_token(id)
    }
    fn spawn_session(&self, id: SessionId, future: impl Future<Output = bool> + Send + 'static) {
        self.inner.spawn_session(id, future);
    }
}
