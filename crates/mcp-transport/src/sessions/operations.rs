use super::{Error, Scoped, entry::Entry, stream::SessionStream};
use rmcp::{model::ClientJsonRpcMessage, transport::streamable_http_server::session::SessionId};
use std::sync::Arc;

pub(crate) fn charge<T>(entry: &Arc<Entry<T>>, stream: bool, get: bool) -> Result<(), Error> {
    let pool = entry.pool.upgrade().ok_or(Error::Unavailable)?;
    let mut state = entry.state.lock().unwrap();
    if entry.closed.is_cancelled() {
        return Err(Error::Unavailable);
    }
    if state.messages >= pool.config.messages
        || (stream && !get && state.request_streams >= pool.config.streams)
        || (get && state.get_used)
    {
        return Err(Error::Limit);
    }
    state.messages += 1;
    state.streams += usize::from(stream);
    state.request_streams += usize::from(stream && !get);
    state.get_used |= get;
    Ok(())
}
pub(crate) async fn run<T, V, E>(
    entry: &Arc<Entry<T>>,
    future: impl Future<Output = Result<V, E>>,
) -> Result<V, Error> {
    tokio::select! {
        _ = entry.closed.cancelled() => Err(Error::Unavailable),
        result = future => result.map_err(|_| { entry.retire(); Error::Transport }),
    }
}
impl<T: Clone + Send + Sync + 'static> Scoped<T> {
    pub(crate) async fn request_stream(
        &self,
        id: &SessionId,
        message: ClientJsonRpcMessage,
    ) -> Result<SessionStream<T>, Error> {
        let entry = self.entry(id)?;
        charge(&entry, true, false)?;
        let lease = SessionStream::lease(entry.clone(), false);
        let receiver = run(&entry, entry.handle.establish_request_wise_channel()).await?;
        run(
            &entry,
            entry.handle.push_message(message, receiver.http_request_id),
        )
        .await?;
        Ok(lease.attach(receiver.inner))
    }
}
