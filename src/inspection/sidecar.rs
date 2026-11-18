//! AGENT-254 — scanners that run outside Locksmith (ML classifiers such
//! as PromptGuard 2 or CodeShield) behind a Unix socket.
//!
//! One HTTP/1.1 request per scan: `POST /scan` with
//! `{"direction": "request"|"response", "text": ...}`, answered with
//! `{"hits": [{"rule", "start", "end", "score"}]}` (byte offsets into
//! `text`). A non-200, a malformed answer, a timeout or a socket error is
//! a [`ScanError`], so the route's `on_error` decides. The process behind
//! the socket must run as Locksmith's own user (AGENT-150): text sent to
//! it may hold secrets, so a socket held by anyone else is refused.
//!
//! Sidecars do not take part in streamed-response windows: a classifier
//! scores whole texts, not a sliding tail.

use super::{Direction, Hit, ScanError, Scanner};
use serde::Deserialize;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::{Duration, Instant};

/// Largest answer read from a sidecar.
const MAX_ANSWER: usize = 1 << 20;

pub struct Sidecar {
    id: String,
    socket: PathBuf,
    timeout: Duration,
}

#[derive(Deserialize)]
struct Answer {
    hits: Vec<AnswerHit>,
}

#[derive(Deserialize)]
struct AnswerHit {
    rule: String,
    start: usize,
    end: usize,
}

impl Sidecar {
    pub fn new(name: &str, socket: PathBuf, timeout: Duration) -> Self {
        Self {
            id: format!("sidecar:{name}"),
            socket,
            timeout,
        }
    }

    fn call(&self, text: &str, direction: Direction) -> Result<Vec<u8>, String> {
        // The sooner of this call's timeout and the whole scan's deadline
        // (AGENT-276): once the scan's has passed, no call is made.
        let own = Instant::now() + self.timeout;
        let deadline = crate::inspection::scan_deadline().map_or(own, |scan| scan.min(own));
        let mut stream = self.connect(deadline)?;
        check_owner(
            peer_uid(&stream).map_err(|e| format!("peer: {e}"))?,
            own_uid(),
        )?;
        let body = serde_json::json!({
            "direction": match direction {
                Direction::Request => "request",
                Direction::Response => "response",
            },
            "text": text,
        })
        .to_string();
        let request = format!(
            "POST /scan HTTP/1.1\r\nHost: locksmith\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        send(&mut stream, request.as_bytes(), deadline)?;
        let mut answer = Vec::new();
        let mut chunk = [0u8; 8192];
        loop {
            stream
                .set_read_timeout(Some(remaining(deadline)?))
                .map_err(|e| e.to_string())?;
            let n = stream.read(&mut chunk).map_err(|e| format!("read: {e}"))?;
            if n == 0 {
                return Ok(answer);
            }
            if answer.len() + n > MAX_ANSWER {
                return Err("answer too large".into());
            }
            answer.extend_from_slice(&chunk[..n]);
        }
    }
}

impl Sidecar {
    /// Connect within `deadline`. A Unix-socket `connect` waits for room in
    /// the sidecar's backlog for up to the socket's send timeout, so setting
    /// it first bounds a sidecar that stopped accepting (Codex P1). Where
    /// the platform refuses a full backlog outright, that is an error too.
    fn connect(&self, deadline: Instant) -> Result<UnixStream, String> {
        use socket2::{Domain, SockAddr, Socket, Type};
        let addr = SockAddr::unix(&self.socket).map_err(|e| format!("connect: {e}"))?;
        let socket =
            Socket::new(Domain::UNIX, Type::STREAM, None).map_err(|e| format!("connect: {e}"))?;
        socket
            .set_write_timeout(Some(remaining(deadline)?))
            .map_err(|e| format!("connect: {e}"))?;
        socket.connect(&addr).map_err(|e| match e.kind() {
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => {
                "connect: timed out".to_string()
            }
            _ => format!("connect: {e}"),
        })?;
        Ok(socket.into())
    }
}

impl Scanner for Sidecar {
    fn id(&self) -> &str {
        &self.id
    }

    /// A classifier scores a whole text; it has no match length.
    fn max_match_len(&self) -> usize {
        0
    }

    fn streams(&self) -> bool {
        false
    }

    fn scan(&self, text: &str, direction: Direction) -> Result<Vec<Hit>, ScanError> {
        let fail = |why: String| ScanError(format!("{}: {why}", self.id));
        let raw = self.call(text, direction).map_err(fail)?;
        let body = http_body(&raw).map_err(fail)?;
        let answer: Answer = serde_json::from_slice(body).map_err(|e| fail(malformed(&e)))?;
        answer
            .hits
            .into_iter()
            .map(|h| {
                if h.start > h.end || h.end > text.len() {
                    return Err(fail(format!("hit {}..{} outside the text", h.start, h.end)));
                }
                Ok(Hit {
                    rule: plain_rule(&h.rule),
                    start: h.start,
                    end: h.end,
                    flag_only: false,
                })
            })
            .collect()
    }
}

/// The longest rule name a sidecar hit keeps (AGENT-278).
const MAX_RULE_LEN: usize = 64;

/// A sidecar's rule name goes into the audit row, so keep it short and
/// plain: other characters become `_`. The hit itself is kept, so a
/// detection is never lost to an odd name.
fn plain_rule(rule: &str) -> String {
    rule.chars()
        .take(MAX_RULE_LEN)
        .map(|c| {
            if c.is_ascii_alphanumeric() || "._:-".contains(c) {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// Write `bytes` within `deadline`. The socket is non-blocking while it
/// writes, and each wait for room is one `poll` given only the time left.
/// A send timeout instead bounds each of the kernel's waits, and one
/// `write` can wait many times when the send buffer is smaller than the
/// write (macOS buffers 8 KiB on an AF_UNIX stream), so a sidecar that
/// frees a little before each wait expired could stretch the call
/// (AGENT-278).
fn send(stream: &mut UnixStream, bytes: &[u8], deadline: Instant) -> Result<(), String> {
    stream
        .set_nonblocking(true)
        .map_err(|e| format!("write: {e}"))?;
    let sent = send_nonblocking(stream, bytes, deadline);
    stream
        .set_nonblocking(false)
        .map_err(|e| format!("write: {e}"))?;
    sent
}

fn send_nonblocking(
    stream: &mut UnixStream,
    bytes: &[u8],
    deadline: Instant,
) -> Result<(), String> {
    let mut sent = 0;
    while sent < bytes.len() {
        match stream.write(&bytes[sent..]) {
            Ok(0) => return Err("write: closed".into()),
            Ok(n) => sent += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                wait_writable(stream, deadline)?;
            }
            Err(e) => return Err(format!("write: {e}")),
        }
    }
    Ok(())
}

/// Wait until `stream` has room to write, or `deadline`.
fn wait_writable(stream: &UnixStream, deadline: Instant) -> Result<(), String> {
    use std::os::fd::AsRawFd;
    let left = remaining(deadline).map_err(|_| "write: timed out".to_string())?;
    // Rounded up, so a wait never ends before the time left.
    let ms = left.as_nanos().div_ceil(1_000_000).min(i32::MAX as u128) as i32;
    let mut fd = libc::pollfd {
        fd: stream.as_raw_fd(),
        events: libc::POLLOUT,
        revents: 0,
    };
    // SAFETY: `fd` is one valid pollfd for the duration of the call.
    match unsafe { libc::poll(&mut fd, 1, ms) } {
        0 => Err("write: timed out".into()),
        -1 => {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::Interrupted {
                Ok(())
            } else {
                Err(format!("write: {e}"))
            }
        }
        // Writable, or an error or hang-up the next write reports.
        _ => Ok(()),
    }
}

/// Time left before `deadline`, or the timeout error. Never under a
/// microsecond: socket2 truncates to microseconds, and a zero socket
/// timeout means none at all.
fn remaining(deadline: Instant) -> Result<Duration, String> {
    at_least_a_microsecond(deadline.saturating_duration_since(Instant::now()))
}

/// `left`, raised to a microsecond, or the timeout error when it is zero.
fn at_least_a_microsecond(left: Duration) -> Result<Duration, String> {
    if left.is_zero() {
        return Err("timed out".into());
    }
    Ok(left.max(Duration::from_micros(1)))
}

/// A malformed answer, described without quoting it: serde's message can
/// carry the answer's own text, and the error is written to the audit row.
fn malformed(e: &serde_json::Error) -> String {
    format!(
        "answer: malformed ({:?} at line {} column {})",
        e.classify(),
        e.line(),
        e.column()
    )
}

/// The body of a 200 answer read to end of stream.
fn http_body(raw: &[u8]) -> Result<&[u8], String> {
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or("no HTTP header")?;
    let head = std::str::from_utf8(&raw[..split]).map_err(|_| "header is not text")?;
    let status = head.split_whitespace().nth(1).unwrap_or_default();
    if status != "200" {
        // Only a well-formed status code is quoted: the error is audited.
        return Err(
            if status.len() == 3 && status.bytes().all(|b| b.is_ascii_digit()) {
                format!("status {status}")
            } else {
                "status is not 200".into()
            },
        );
    }
    if head
        .to_ascii_lowercase()
        .contains("transfer-encoding: chunked")
    {
        return Err("chunked answers are not supported".into());
    }
    Ok(&raw[split + 4..])
}

/// Refuse a sidecar running as another user (AGENT-150).
pub fn check_owner(peer: u32, own: u32) -> Result<(), String> {
    if peer == own {
        Ok(())
    } else {
        Err(format!(
            "socket served by uid {peer}, not Locksmith's {own}"
        ))
    }
}

fn own_uid() -> u32 {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() }
}

/// The effective uid of the process at the other end of `stream`.
pub fn peer_uid(stream: &UnixStream) -> std::io::Result<u32> {
    use std::os::fd::AsRawFd;
    let fd = stream.as_raw_fd();
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        let mut cred = libc::ucred {
            pid: 0,
            uid: 0,
            gid: 0,
        };
        let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        // SAFETY: `cred` and `len` are valid for writes of the sizes given.
        let rc = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&mut cred as *mut libc::ucred).cast(),
                &mut len,
            )
        };
        if rc != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(cred.uid)
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        let (mut uid, mut gid) = (0, 0);
        // SAFETY: `uid` and `gid` are valid for writes.
        if unsafe { libc::getpeereid(fd, &mut uid, &mut gid) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(uid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;

    /// A one-shot sidecar answering every connection with `answer` after
    /// `delay`. Returns its socket path; the TempDir must outlive it.
    fn serve(dir: &tempfile::TempDir, answer: &'static str, delay: Duration) -> PathBuf {
        let path = dir.path().join("s.sock");
        let listener = UnixListener::bind(&path).unwrap();
        std::thread::spawn(move || {
            for conn in listener.incoming() {
                let Ok(mut conn) = conn else { return };
                let mut buf = [0u8; 65536];
                let _ = conn.read(&mut buf);
                std::thread::sleep(delay);
                let _ = conn.write_all(answer.as_bytes());
            }
        });
        path
    }

    const HIT: &str = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n\
        {\"hits\":[{\"rule\":\"promptguard\",\"start\":0,\"end\":5,\"score\":0.93}]}";

    /// Codex P1 — `timeout_ms` bounds connecting too. A sidecar that never
    /// accepts, with its backlog full, used to block `connect` forever.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_sidecar_that_never_accepts_times_out() {
        use socket2::{Domain, SockAddr, Socket, Type};
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("full.sock");
        let addr = SockAddr::unix(&path).unwrap();
        let listener = Socket::new(Domain::UNIX, Type::STREAM, None).unwrap();
        listener.bind(&addr).unwrap();
        listener.listen(0).unwrap();
        let mut queued = Vec::new();
        loop {
            let c = Socket::new(Domain::UNIX, Type::STREAM, None).unwrap();
            c.set_nonblocking(true).unwrap();
            match c.connect(&addr) {
                Ok(()) => queued.push(c),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => panic!("filling the backlog: {e}"),
            }
            assert!(queued.len() < 1024, "backlog never filled");
        }
        let s = Sidecar::new("pg", path, Duration::from_millis(200));
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(s.scan("hello", Direction::Response).is_err());
        });
        let failed = rx
            .recv_timeout(Duration::from_secs(3))
            .expect("connect must honour timeout_ms");
        assert!(failed);
        drop((listener, queued));
    }

    /// AGENT-278 (Codex Medium) — a sidecar that reads a large request
    /// slowly, but never slowly enough for one write to time out, cannot
    /// hold the call past its deadline.
    #[test]
    fn a_slow_reading_sidecar_cannot_outrun_the_deadline() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("slow.sock");
        let listener = UnixListener::bind(&path).unwrap();
        std::thread::spawn(move || {
            let Ok((mut conn, _)) = listener.accept() else {
                return;
            };
            // 64 KiB every 100 ms: each write makes progress well within
            // 300 ms, but the 4 MiB request takes over six seconds.
            let mut buf = vec![0u8; 64 << 10];
            while matches!(conn.read(&mut buf), Ok(n) if n > 0) {
                std::thread::sleep(Duration::from_millis(100));
            }
        });
        let s = Sidecar::new("pg", path, Duration::from_millis(300));
        let text = "x".repeat(4 << 20);
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let start = Instant::now();
            let result = s.scan(&text, Direction::Response);
            let _ = tx.send((result.map_err(|e| e.0), start.elapsed()));
        });
        let (result, took) = rx
            .recv_timeout(Duration::from_secs(5))
            .expect("the write must honour timeout_ms");
        let err = result.unwrap_err();
        assert!(err.contains("timed out"), "{err}");
        assert!(took < Duration::from_secs(2), "{took:?}");
    }

    /// AGENT-278 — with a send buffer smaller than a write (as on macOS,
    /// where an AF_UNIX stream buffers 8 KiB), one write can wait for room
    /// many times. A reader that frees a little just before each wait
    /// would time out must still not stretch `send` past its deadline.
    #[test]
    fn a_small_send_buffer_cannot_stretch_a_write() {
        let (mut ours, mut theirs) = UnixStream::pair().unwrap();
        socket2::SockRef::from(&ours)
            .set_send_buffer_size(4096)
            .unwrap();
        let reader = std::thread::spawn(move || {
            let mut buf = [0u8; 2048];
            loop {
                std::thread::sleep(Duration::from_millis(80));
                match theirs.read(&mut buf) {
                    Ok(n) if n > 0 => {}
                    _ => return,
                }
            }
        });
        let start = Instant::now();
        let result = send(
            &mut ours,
            &vec![b'x'; 1 << 20],
            start + Duration::from_millis(300),
        );
        let took = start.elapsed();
        drop(ours);
        reader.join().unwrap();
        assert!(result.unwrap_err().contains("timed out"));
        assert!(took < Duration::from_millis(450), "{took:?}");
    }

    /// Codex P2 — a malformed answer's own text never reaches the error,
    /// which is written to the audit row.
    #[test]
    fn sidecar_errors_do_not_quote_the_answer() {
        const BAD_FIELD: &str = "HTTP/1.1 200 OK\r\n\r\n\
            {\"hits\":[{\"rule\":\"x\",\"start\":\"MARKER-7f3a\",\"end\":1}]}";
        const BAD_STATUS: &str = "HTTP/1.1 MARKER-7f3a OK\r\n\r\n{}";
        for answer in [BAD_FIELD, BAD_STATUS] {
            let dir = tempfile::TempDir::new().unwrap();
            let s = Sidecar::new(
                "pg",
                serve(&dir, answer, Duration::ZERO),
                Duration::from_secs(2),
            );
            let err = s.scan("hello", Direction::Response).unwrap_err();
            assert!(!err.0.contains("MARKER"), "{}", err.0);
        }
    }

    /// AGENT-276 / Codex P1 — every call shares the scan's deadline, so a
    /// body with many strings stops calling a slow sidecar once it passes.
    #[test]
    fn calls_stop_at_the_scan_deadline() {
        let dir = tempfile::TempDir::new().unwrap();
        let s = Sidecar::new(
            "pg",
            serve(&dir, HIT, Duration::from_millis(300)),
            Duration::from_secs(2),
        );
        let start = Instant::now();
        // The first call takes 300 ms of a 400 ms deadline; the second
        // would need 600 ms.
        let results = crate::inspection::with_deadline(start + Duration::from_millis(400), || {
            (0..10)
                .map(|_| s.scan("hello world", Direction::Response).is_ok())
                .collect::<Vec<_>>()
        });
        assert!(results[0], "the first call fits in the deadline");
        assert!(results[1..].iter().all(|ok| !ok), "{results:?}");
        assert!(
            start.elapsed() < Duration::from_millis(1500),
            "{:?}",
            start.elapsed()
        );
    }

    /// A socket timeout under a microsecond rounds to zero, which means
    /// "no timeout", so the time left is never handed over that small.
    #[test]
    fn time_left_is_never_below_a_microsecond() {
        for nanos in [1, 500, 999] {
            assert_eq!(
                at_least_a_microsecond(Duration::from_nanos(nanos)),
                Ok(Duration::from_micros(1))
            );
        }
        assert_eq!(
            at_least_a_microsecond(Duration::from_millis(5)),
            Ok(Duration::from_millis(5))
        );
        assert!(at_least_a_microsecond(Duration::ZERO).is_err());
    }

    /// AGENT-278: a sidecar's rule name reaches the audit row, so it is
    /// cut to `MAX_RULE_LEN` characters of a plain set; the hit is kept.
    #[test]
    fn a_sidecar_rule_name_is_bounded_and_plain() {
        let rule = format!("{}{}", "bad\u{1b}[31m\nrule ", "x".repeat(500));
        let body = serde_json::json!({"hits": [{"rule": rule, "start": 0, "end": 5}]});
        let answer: &'static str = Box::leak(
            format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{body}")
                .into_boxed_str(),
        );
        let dir = tempfile::TempDir::new().unwrap();
        let s = Sidecar::new(
            "pg",
            serve(&dir, answer, Duration::ZERO),
            Duration::from_secs(2),
        );
        let hits = s.scan("hello world", Direction::Response).unwrap();
        assert_eq!(hits.len(), 1);
        let got = &hits[0].rule;
        assert_eq!(got.chars().count(), MAX_RULE_LEN, "{got}");
        assert!(got.starts_with("bad__31m_rule_x"), "{got}");
        assert!(
            got.chars()
                .all(|c| c.is_ascii_alphanumeric() || "._:-".contains(c)),
            "{got}"
        );
    }

    #[test]
    fn hits_from_the_sidecar_are_reported() {
        let dir = tempfile::TempDir::new().unwrap();
        let s = Sidecar::new(
            "pg",
            serve(&dir, HIT, Duration::ZERO),
            Duration::from_secs(2),
        );
        let hits = s.scan("hello world", Direction::Response).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(
            (hits[0].rule.as_str(), hits[0].start, hits[0].end),
            ("promptguard", 0, 5)
        );
        assert_eq!(s.id(), "sidecar:pg");
    }

    #[test]
    fn a_missing_socket_is_an_error() {
        let dir = tempfile::TempDir::new().unwrap();
        let s = Sidecar::new("pg", dir.path().join("absent.sock"), Duration::from_secs(1));
        let err = s.scan("x", Direction::Request).unwrap_err();
        assert!(err.0.starts_with("sidecar:pg: connect"), "{}", err.0);
    }

    #[test]
    fn the_timeout_is_honoured() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = serve(&dir, HIT, Duration::from_secs(3));
        let s = Sidecar::new("pg", path, Duration::from_millis(200));
        let started = Instant::now();
        assert!(s.scan("x", Direction::Request).is_err());
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "{:?}",
            started.elapsed()
        );
    }

    #[test]
    fn a_non_200_or_bad_hit_is_an_error() {
        let dir = tempfile::TempDir::new().unwrap();
        let s = Sidecar::new(
            "pg",
            serve(&dir, "HTTP/1.1 500 Oops\r\n\r\n{}", Duration::ZERO),
            Duration::from_secs(2),
        );
        assert!(
            s.scan("x", Direction::Request)
                .unwrap_err()
                .0
                .contains("status 500")
        );
        let dir = tempfile::TempDir::new().unwrap();
        let s = Sidecar::new(
            "pg",
            serve(&dir, HIT, Duration::ZERO),
            Duration::from_secs(2),
        );
        assert!(
            s.scan("abc", Direction::Request)
                .unwrap_err()
                .0
                .contains("outside")
        );
    }

    #[test]
    fn the_peer_uid_is_ours_and_another_is_refused() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = serve(&dir, HIT, Duration::ZERO);
        let stream = UnixStream::connect(path).unwrap();
        assert_eq!(peer_uid(&stream).unwrap(), own_uid());
        assert!(check_owner(own_uid(), own_uid()).is_ok());
        assert!(check_owner(own_uid() + 1, own_uid()).is_err());
    }
}
