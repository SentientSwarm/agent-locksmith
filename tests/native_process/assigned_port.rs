//! Read the acknowledged bound address from the owned fixture daemon log.
use serde_json::Value;
use std::{net::SocketAddr, path::Path};

pub fn read(dir: &Path) -> Option<u16> {
    let log = std::fs::read_to_string(dir.join("daemon.log")).unwrap();
    let mut port = None;
    for event in log
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
    {
        if event["fields"]["message"] == "agent listener (mTLS) bound"
            && let Some(addr) = event["fields"]["addr"].as_str()
        {
            port = Some(addr.parse::<SocketAddr>().unwrap().port());
        }
    }
    port
}
