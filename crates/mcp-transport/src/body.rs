use crate::{Error, Limits, Metrics};
use bytes::Bytes;
use reqwest::Response;

pub(crate) struct Body {
    response: Response,
    limits: Limits,
    metrics: Metrics,
    received: usize,
    chunks: usize,
}
impl Body {
    pub(crate) fn new(response: Response, limits: Limits, metrics: Metrics) -> Result<Self, Error> {
        crate::headers::body(&response, limits)?;
        metrics.open();
        Ok(Self {
            response,
            limits,
            metrics,
            received: 0,
            chunks: 0,
        })
    }
    pub(crate) async fn next(&mut self) -> Result<Option<Bytes>, Error> {
        let Some(chunk) = self
            .response
            .chunk()
            .await
            .map_err(crate::request::io_error)?
        else {
            return Ok(None);
        };
        self.metrics.received(chunk.len());
        self.chunks += 1;
        if chunk.len() > self.limits.chunk_bytes {
            return Err(Error("chunk_bytes"));
        }
        if self.chunks > self.limits.chunks {
            return Err(Error("chunks"));
        }
        if chunk.len() > self.limits.response_bytes - self.received {
            return Err(Error("response_bytes"));
        }
        self.received += chunk.len();
        Ok(Some(chunk))
    }
    pub(crate) async fn collect(mut self) -> Result<Vec<u8>, Error> {
        let mut bytes = Vec::with_capacity(self.limits.response_bytes);
        while let Some(chunk) = self.next().await? {
            self.metrics.admitted(chunk.len());
            bytes.extend_from_slice(&chunk);
            self.metrics.retained(bytes.len());
        }
        Ok(bytes)
    }
}
impl Drop for Body {
    fn drop(&mut self) {
        self.metrics.close();
    }
}
