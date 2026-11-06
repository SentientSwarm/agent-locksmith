use super::{Error, Result};
use std::{
    collections::BTreeMap,
    net::{IpAddr, SocketAddr},
    sync::Mutex,
};

#[derive(Default)]
pub struct Listeners(Mutex<BTreeMap<&'static str, Option<SocketAddr>>>);
impl Listeners {
    pub fn expect(&self, name: &'static str) {
        self.0.lock().expect("listeners").insert(name, None);
    }
    pub fn bound(&self, name: &'static str, addr: SocketAddr) {
        self.0.lock().expect("listeners").insert(name, Some(addr));
    }
    fn ports(&self) -> Result<Vec<u16>> {
        self.0
            .lock()
            .expect("listeners")
            .values()
            .map(|v| v.map(|a| a.port()).ok_or(Error("listeners_pending")))
            .collect()
    }
}
pub async fn resolve(
    endpoint: &str,
    private: bool,
    listeners: &Listeners,
) -> Result<Vec<SocketAddr>> {
    let url = endpoint_url(endpoint)?;
    let host = url
        .host_str()
        .ok_or(Error("destination_invalid"))?
        .trim_matches(['[', ']']);
    let port = url
        .port_or_known_default()
        .ok_or(Error("destination_invalid"))?;
    let ports = listeners.ports()?;
    let local = super::interfaces::addresses()?;
    let resolved = tokio::net::lookup_host((host, port))
        .await
        .map_err(|_| Error("dns_failed"))?;
    approved(resolved, private, &local, &ports)
}
fn approved(
    resolved: impl Iterator<Item = SocketAddr>,
    private: bool,
    local: &[IpAddr],
    ports: &[u16],
) -> Result<Vec<SocketAddr>> {
    let mut addresses = Vec::new();
    for addr in resolved {
        if addresses.len() >= 32 {
            return Err(Error("dns_limit"));
        }
        approve(addr, private, local, ports)?;
        addresses.push(addr);
    }
    addresses.sort();
    addresses.dedup();
    if addresses.is_empty() {
        return Err(Error("dns_empty"));
    }
    Ok(addresses)
}
pub fn approve(addr: SocketAddr, private: bool, local: &[IpAddr], ports: &[u16]) -> Result<()> {
    if ports.contains(&addr.port()) && (local.contains(&addr.ip()) || addr.ip().is_loopback()) {
        return Err(Error("self_destination"));
    }
    let allowed = match addr.ip() {
        IpAddr::V4(ip) => v4(ip.octets(), private),
        IpAddr::V6(ip) => {
            if ip.to_ipv4_mapped().is_some() {
                false
            } else if ip.is_loopback() || ip.is_unique_local() {
                private
            } else {
                ip.segments()[0] & 0xe000 == 0x2000
                    && ip.segments()[..2] != [0x2001, 0xdb8]
                    && !(ip.segments()[0] == 0x2001 && ip.segments()[1] < 0x200)
                    && ip.segments()[0] != 0x2002
                    && !(ip.segments()[0] == 0x3fff && ip.segments()[1] < 0x1000)
            }
        }
    };
    if allowed {
        Ok(())
    } else {
        Err(Error("destination_forbidden"))
    }
}
fn v4(a: [u8; 4], private: bool) -> bool {
    let [x, y, z, _] = a;
    if x == 0
        || x >= 224
        || (x == 169 && y == 254)
        || (x == 192 && y == 0 && (z == 0 || z == 2))
        || (x == 192 && y == 88 && z == 99)
        || (x == 198 && (y == 18 || y == 19))
        || (x == 198 && y == 51 && z == 100)
        || (x == 203 && y == 0 && z == 113)
    {
        return false;
    }
    if x == 10
        || x == 127
        || (x == 172 && (16..32).contains(&y))
        || (x == 192 && y == 168)
        || (x == 100 && (64..128).contains(&y))
    {
        return private;
    }
    true
}

fn endpoint_url(endpoint: &str) -> Result<reqwest::Url> {
    let url = reqwest::Url::parse(endpoint).map_err(|_| Error("destination_invalid"))?;
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(Error("destination_invalid"));
    }
    Ok(url)
}
