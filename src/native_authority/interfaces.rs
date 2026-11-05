//! Read local interface addresses without changing routing or interface state.
use super::{Error, Result};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

struct List(*mut libc::ifaddrs);
impl Drop for List {
    fn drop(&mut self) {
        // SAFETY: pointer came from successful getifaddrs and is freed once.
        unsafe { libc::freeifaddrs(self.0) };
    }
}
pub(super) fn addresses() -> Result<Vec<IpAddr>> {
    let mut first = std::ptr::null_mut();
    // SAFETY: getifaddrs writes an allocated linked list into a valid pointer.
    if unsafe { libc::getifaddrs(&mut first) } != 0 {
        return Err(Error("local_addresses_unavailable"));
    }
    let list = List(first);
    let mut next = list.0;
    let mut result = vec![
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(Ipv6Addr::LOCALHOST),
    ];
    let mut count = 0;
    while !next.is_null() {
        count += 1;
        if count > 4096 {
            return Err(Error("local_addresses_limit"));
        }
        // SAFETY: getifaddrs list stays live until List's drop, every node is valid.
        let entry = unsafe { &*next };
        if let Some(ip) = address(entry.ifa_addr) {
            result.push(ip);
        }
        next = entry.ifa_next;
    }
    result.sort();
    result.dedup();
    Ok(result)
}
fn address(ptr: *const libc::sockaddr) -> Option<IpAddr> {
    if ptr.is_null() {
        return None;
    }
    // SAFETY: ifa_addr is null or an address whose family identifies its layout.
    unsafe {
        match i32::from((*ptr).sa_family) {
            libc::AF_INET => {
                let addr = &*ptr.cast::<libc::sockaddr_in>();
                Some(IpAddr::V4(Ipv4Addr::from(
                    addr.sin_addr.s_addr.to_ne_bytes(),
                )))
            }
            libc::AF_INET6 => {
                let addr = &*ptr.cast::<libc::sockaddr_in6>();
                Some(IpAddr::V6(Ipv6Addr::from(addr.sin6_addr.s6_addr)))
            }
            _ => None,
        }
    }
}
