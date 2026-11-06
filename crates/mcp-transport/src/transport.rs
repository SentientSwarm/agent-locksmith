use crate::Client;
use rmcp::transport::{
    StreamableHttpClientTransport, common::client_side_sse::SseRetryPolicy,
    streamable_http_client::StreamableHttpClientTransportConfig,
};
use std::{sync::Arc, time::Duration};

#[derive(Debug)]
struct NeverRetry;
impl SseRetryPolicy for NeverRetry {
    fn retry(&self, _: usize) -> Option<Duration> {
        None
    }
}
impl Client {
    pub fn client_config() -> rmcp::model::ClientConfig {
        rmcp::model::ClientConfig::default()
            .with_protocol_version(rmcp::model::ProtocolVersion::V_2025_11_25)
    }

    /// Use with ClientConfig protocol_version V_2025_11_25. No automatic replay.
    pub fn transport(
        &self,
        uri: impl Into<Arc<str>>,
        auth: Option<String>,
    ) -> StreamableHttpClientTransport<Self> {
        let mut config = StreamableHttpClientTransportConfig::with_uri(uri);
        config.auth_header = auth;
        config.retry_config = Arc::new(NeverRetry);
        config.reinit_on_expired_session = false;
        config.channel_buffer_capacity = 8;
        config.max_concurrent_requests = 4;
        config.max_sse_event_size = self.limits.event_bytes;
        config.control_request_timeout = Duration::from_millis(self.limits.timeout_ms);
        let mut client = self.clone();
        client.get_started = Arc::default();
        StreamableHttpClientTransport::with_client(client, config)
    }
}
