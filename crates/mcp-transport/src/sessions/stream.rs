use super::entry::Entry;
use futures_util::Stream;
use rmcp::transport::streamable_http_server::session::ServerSseMessage;
use std::{
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::sync::mpsc::Receiver;

/// An unfinished HTTP response drop retires the session before more admission.
pub struct SessionStream<T> {
    entry: Arc<Entry<T>>,
    receiver: Option<Receiver<ServerSseMessage>>,
    initial: Option<ServerSseMessage>,
    finished: bool,
    standalone: bool,
}
impl<T> SessionStream<T> {
    pub(crate) fn lease(entry: Arc<Entry<T>>, standalone: bool) -> Self {
        Self {
            entry,
            receiver: None,
            initial: None,
            finished: false,
            standalone,
        }
    }
    pub(crate) fn initial(mut self, response: ServerSseMessage) -> Self {
        self.initial = Some(response);
        self
    }
    pub(crate) fn attach(mut self, receiver: Receiver<ServerSseMessage>) -> Self {
        self.receiver = Some(receiver);
        self
    }
}
impl<T> Stream for SessionStream<T> {
    type Item = ServerSseMessage;
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        if let Some(response) = this.initial.take() {
            // The SDK client stops at the final initialize event, before EOF.
            this.finished = true;
            return Poll::Ready(Some(response));
        }
        let result = match &mut this.receiver {
            Some(rx) => rx.poll_recv(cx),
            None => Poll::Ready(None),
        };
        if matches!(result, Poll::Ready(None)) {
            this.finished = true;
        }
        result
    }
}
impl<T> Drop for SessionStream<T> {
    fn drop(&mut self) {
        {
            let mut state = self.entry.state.lock().unwrap();
            state.streams -= 1;
            state.request_streams -= usize::from(!self.standalone);
        }
        self.entry.try_release();
        if !self.finished || self.standalone {
            self.entry.retire();
        }
    }
}
