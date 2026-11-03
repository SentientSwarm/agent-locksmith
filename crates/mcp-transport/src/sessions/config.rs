use super::Error;
use std::time::Duration;

/// Verified identities and an authority fingerprint, never bearer secrets.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Scope {
    pub owner: String,
    pub connection: String,
    pub authority: String,
}
impl Scope {
    pub(crate) fn validate(&self) -> Result<(), Error> {
        if [&self.owner, &self.connection, &self.authority]
            .into_iter()
            .any(|s| s.is_empty() || s.len() > 256)
        {
            return Err(Error::Config);
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct Config {
    pub total: usize,
    pub per_owner: usize,
    pub per_connection: usize,
    pub messages: usize,
    pub streams: usize,
    pub channel: usize,
    pub handshake: Duration,
    pub lifetime: Duration,
    pub idle: Duration,
    pub cleanup_grace: Duration,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            total: 256,
            per_owner: 16,
            per_connection: 16,
            messages: 256,
            streams: 4,
            channel: 8,
            handshake: Duration::from_secs(5),
            lifetime: Duration::from_secs(900),
            idle: Duration::from_secs(300),
            cleanup_grace: Duration::from_millis(250),
        }
    }
}
impl Config {
    pub(crate) fn validate(&self) -> Result<(), Error> {
        let counts = [
            (self.total, 4096),
            (self.per_owner, 256),
            (self.per_connection, 256),
            (self.messages, 4096),
            (self.streams, 32),
            (self.channel, 64),
        ];
        let times = [
            (self.handshake, 30),
            (self.lifetime, 3600),
            (self.idle, 900),
            (self.cleanup_grace, 5),
        ];
        if counts.iter().any(|(v, max)| *v == 0 || v > max)
            || times
                .iter()
                .any(|(v, max)| v.is_zero() || *v > Duration::from_secs(*max))
        {
            return Err(Error::Config);
        }
        Ok(())
    }

    pub(crate) fn sdk(
        &self,
    ) -> rmcp::transport::streamable_http_server::session::local::SessionConfig {
        let mut sdk =
            rmcp::transport::streamable_http_server::session::local::SessionConfig::default();
        sdk.channel_capacity = self.channel;
        sdk.keep_alive = Some(self.idle);
        sdk.init_timeout = Some(self.handshake);
        sdk.sse_retry = None;
        sdk.completed_cache_ttl = Duration::ZERO;
        sdk
    }
}
