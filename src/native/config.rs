use serde::Deserialize;
use std::time::Duration;

#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub upstream_ca_bundle: Option<std::path::PathBuf>,
    pub allowed_hosts: Vec<String>,
    pub allowed_origins: Vec<String>,
    pub ingress: usize,
    pub sessions: usize,
    pub sessions_per_agent: usize,
    pub sessions_per_connection: usize,
    pub messages: usize,
    pub streams: usize,
    pub handshake_ms: u64,
    pub lifetime_ms: u64,
    pub idle_ms: u64,
    pub request_ms: u64,
    pub response_ms: u64,
    pub request_bytes: usize,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            upstream_ca_bundle: None,
            allowed_hosts: vec!["localhost".into(), "127.0.0.1".into(), "[::1]".into()],
            allowed_origins: vec![],
            ingress: 128,
            sessions: 256,
            sessions_per_agent: 16,
            sessions_per_connection: 16,
            messages: 256,
            streams: 4,
            handshake_ms: 5000,
            lifetime_ms: 900_000,
            idle_ms: 300_000,
            request_ms: 10_000,
            response_ms: 60_000,
            request_bytes: 256 * 1024,
        }
    }
}
impl Config {
    pub fn validate(&self) -> Result<(), &'static str> {
        let d = Self::default();
        let bounds = [
            (self.ingress, d.ingress),
            (self.sessions, d.sessions),
            (self.sessions_per_agent, d.sessions_per_agent),
            (self.sessions_per_connection, d.sessions_per_connection),
            (self.messages, d.messages),
            (self.streams, d.streams),
            (self.request_bytes, d.request_bytes),
        ];
        let times = [
            (self.handshake_ms, d.handshake_ms),
            (self.lifetime_ms, d.lifetime_ms),
            (self.idle_ms, d.idle_ms),
            (self.request_ms, d.request_ms),
            (self.response_ms, d.response_ms),
        ];
        if bounds.iter().any(|(n, max)| *n == 0 || n > max)
            || times.iter().any(|(n, max)| *n == 0 || n > max)
            || !self.valid_hosts()
            || self.allowed_origins.len() > 16
            || self.allowed_origins.iter().any(|s| origin(s).is_none())
        {
            return Err("invalid finite MCP configuration");
        }
        Ok(())
    }
    fn valid_hosts(&self) -> bool {
        !self.allowed_hosts.is_empty()
            && self.allowed_hosts.len() <= 16
            && self.allowed_hosts.iter().all(|host| {
                host.len() <= 253
                    && !host.contains(['/', '@', '*', '?', '#'])
                    && origin(&format!("https://{host}")).is_some()
            })
    }
    pub fn sessions(&self) -> locksmith_mcp_transport::sessions::Config {
        locksmith_mcp_transport::sessions::Config {
            total: self.sessions,
            per_owner: self.sessions_per_agent,
            per_connection: self.sessions_per_connection,
            messages: self.messages,
            streams: self.streams,
            handshake: Duration::from_millis(self.handshake_ms),
            lifetime: Duration::from_millis(self.lifetime_ms),
            idle: Duration::from_millis(self.idle_ms),
            ..Default::default()
        }
    }
}
pub(super) fn origin(raw: &str) -> Option<String> {
    let url = reqwest::Url::parse(raw).ok()?;
    (raw.len() <= 512
        && !raw.chars().any(|c| c.is_control() || c == '\\')
        && matches!(url.scheme(), "https" | "http")
        && url.has_host()
        && url.username().is_empty()
        && url.password().is_none()
        && url.path() == "/"
        && url.query().is_none()
        && url.fragment().is_none()
        && raw.trim() == raw
        && !raw.contains('*'))
    .then(|| url.origin().ascii_serialization())
}
