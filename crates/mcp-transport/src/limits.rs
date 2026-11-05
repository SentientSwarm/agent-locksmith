use crate::Error;
use serde::{Deserialize, Serialize};

/// Per HTTP response, including error bodies. No zero/unlimited sentinel.
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    pub response_bytes: usize,
    pub chunk_bytes: usize,
    pub chunks: usize,
    pub event_bytes: usize,
    pub events: usize,
    pub json_depth: usize,
    pub json_units: usize,
    pub timeout_ms: u64,
    pub connect_timeout_ms: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            response_bytes: 256 * 1024,
            chunk_bytes: 256 * 1024,
            chunks: 8192,
            event_bytes: 64 * 1024,
            events: 128,
            json_depth: 32,
            json_units: 8192,
            timeout_ms: 10_000,
            connect_timeout_ms: 3_000,
        }
    }
}

impl Limits {
    pub(crate) fn validate(self) -> Result<Self, Error> {
        let sizes = [self.response_bytes, self.chunk_bytes, self.event_bytes];
        let counts = [self.chunks, self.events, self.json_units];
        if sizes.iter().any(|n| *n == 0 || *n > 8 * 1024 * 1024)
            || counts.iter().any(|n| *n == 0 || *n > 65536)
            || !(1..=64).contains(&self.json_depth)
            || !(1..=120_000).contains(&self.timeout_ms)
            || !(1..=self.timeout_ms).contains(&self.connect_timeout_ms)
        {
            return Err(Error("invalid_limits"));
        }
        Ok(self)
    }
}
