//! AGENT-295 — a port for a daemon to bind later, from its config.
//!
//! A port probed with `bind(0)` comes from the OS's ephemeral range, and
//! the dozens of daemons, mock servers and outgoing connections a suite
//! runs draw from that range too: one of them can be handed the port
//! before the daemon binds it, and the daemon then fails to start
//! (`callback_bind_failed`). Ports below the ephemeral ranges (Linux
//! 32768 and up, macOS 49152 and up) are never handed out that way. So
//! pick one there, check it is free, and never pick the same one twice
//! in a process.

use std::sync::atomic::{AtomicU64, Ordering};

const FIRST: u64 = 20_000;
const SPAN: u64 = 12_000;
static NEXT: AtomicU64 = AtomicU64::new(0);

pub fn fixed_port() -> u16 {
    // Start each process somewhere else in the span.
    let start = u64::from(std::process::id()).wrapping_mul(7_919) % SPAN;
    for _ in 0..SPAN {
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let port = u16::try_from(FIRST + (start + n) % SPAN).expect("in range");
        if std::net::TcpListener::bind(("127.0.0.1", port)).is_ok() {
            return port;
        }
    }
    panic!("no free port in {FIRST}..{}", FIRST + SPAN);
}
