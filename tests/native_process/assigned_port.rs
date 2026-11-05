//! Read acknowledged bound addresses from the owned fixture daemon log.
use serde_json::Value;
use std::{net::SocketAddr, path::Path};

/// The agent listener's bound port, in either listener mode.
pub fn read(dir: &Path) -> Option<u16> {
    last(dir, |message| {
        message == "agent listener (mTLS) bound" || message.starts_with("agent listener bound")
    })
}

/// The admin HTTPS listener's bound port, in either auth mode.
pub fn admin_https(dir: &Path) -> Option<u16> {
    last(dir, |message| message.starts_with("admin HTTPS"))
}

fn last(dir: &Path, matches: impl Fn(&str) -> bool) -> Option<u16> {
    let log = std::fs::read_to_string(dir.join("daemon.log")).unwrap();
    let mut port = None;
    for event in log
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
    {
        if event["fields"]["message"].as_str().is_some_and(&matches)
            && let Some(addr) = event["fields"]["addr"].as_str()
        {
            port = Some(addr.parse::<SocketAddr>().unwrap().port());
        }
    }
    port
}
