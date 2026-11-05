use axum::{
    body::{Body, BodyDataStream, Bytes},
    response::Response,
};
use futures_util::{StreamExt, stream};
use std::io;
use tokio::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;

struct Output {
    body: BodyDataStream,
    stop: CancellationToken,
    deadline: Instant,
    bytes: usize,
    frames: usize,
}
pub(super) fn bounded(response: Response, stop: CancellationToken, timeout_ms: u64) -> Response {
    let (parts, body) = response.into_parts();
    let output = Output {
        body: body.into_data_stream(),
        stop,
        deadline: Instant::now() + Duration::from_millis(timeout_ms),
        bytes: 0,
        frames: 0,
    };
    let stream = stream::unfold(Some(output), |state| async move {
        let mut state = state?;
        match state.next().await {
            Ok(Some(bytes)) => Some((Ok::<_, io::Error>(bytes), Some(state))),
            Ok(None) => None,
            Err(error) => Some((Err(error), None)),
        }
    });
    Response::from_parts(parts, Body::from_stream(stream))
}
impl Output {
    async fn next(&mut self) -> io::Result<Option<Bytes>> {
        let next = tokio::select! {
            biased;
            _ = self.stop.cancelled() => return Err(io::Error::other("native shutdown")),
            _ = tokio::time::sleep_until(self.deadline) => return Err(io::Error::other("native response deadline")),
            next = self.body.next() => next,
        };
        let Some(bytes) = next else {
            return Ok(None);
        };
        let bytes = bytes.map_err(|_| io::Error::other("native response failed"))?;
        self.bytes += bytes.len();
        self.frames += 1;
        if bytes.len() > 64 * 1024 || self.bytes > 256 * 1024 || self.frames > 1024 {
            return Err(io::Error::other("native response limit"));
        }
        Ok(Some(bytes))
    }
}
