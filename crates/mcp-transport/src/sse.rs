use crate::{Error, Limits, Metrics, body::Body, sse_guard::Guard};
use futures_util::{
    StreamExt,
    stream::{self, BoxStream},
};
use sse_stream::{Error as SseError, Sse, SseStream};

struct State {
    body: Body,
    guard: Guard,
    metrics: Metrics,
}
pub(crate) fn stream(
    body: Body,
    limits: Limits,
    metrics: Metrics,
    validator: Option<crate::ResponseValidator>,
) -> BoxStream<'static, Result<Sse, SseError>> {
    let state = State {
        body,
        guard: Guard::new(limits),
        metrics,
    };
    checked(
        SseStream::from_bytes_stream(bytes(state)).boxed(),
        limits,
        validator,
    )
}
fn bytes(state: State) -> impl futures_util::Stream<Item = Result<bytes::Bytes, Error>> {
    stream::try_unfold(state, |mut state| async move {
        match state.body.next().await? {
            Some(chunk) => {
                let high = state.guard.observe(&chunk)?;
                state.metrics.admitted(chunk.len());
                state.metrics.retained(high);
                Ok::<_, Error>(Some((chunk, state)))
            }
            None => {
                state.guard.finish()?;
                Ok(None)
            }
        }
    })
}
fn checked(
    source: BoxStream<'static, Result<Sse, SseError>>,
    limits: Limits,
    validator: Option<crate::ResponseValidator>,
) -> BoxStream<'static, Result<Sse, SseError>> {
    stream::try_unfold(
        (source, 0usize),
        move |(mut source, mut units)| async move {
            let Some(event) = source.next().await else {
                return Ok(None);
            };
            let event = event.map_err(sanitize)?;
            if let Some(data) = event.data.as_deref().filter(|s| !s.is_empty()) {
                units += crate::json::preflight(data.as_bytes(), limits).map_err(sse_error)?;
                if units > limits.json_units {
                    return Err(sse_error(Error("json_units")));
                }
                if let Some(validate) = validator {
                    let raw =
                        crate::strict_json::parse(data.as_bytes(), limits).map_err(sse_error)?;
                    validate(&raw).map_err(sse_error)?;
                }
                crate::json::decode(data.as_bytes(), limits).map_err(sse_error)?;
            }
            Ok(Some((event, (source, units))))
        },
    )
    .boxed()
}
fn sse_error(error: Error) -> SseError {
    SseError::Body(Box::new(error))
}

fn sanitize(error: SseError) -> SseError {
    if let SseError::Body(ref inner) = error
        && let Some(error) = inner.downcast_ref::<Error>()
    {
        return sse_error(*error);
    }
    sse_error(Error("sse"))
}
