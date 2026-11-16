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
        let deadline = Instant::now() + self.timeout;
        let mut stream = UnixStream::connect(&self.socket).map_err(|e| format!("connect: {e}"))?;
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
        stream
            .set_write_timeout(Some(remaining(deadline)?))
            .map_err(|e| e.to_string())?;
        stream
            .write_all(request.as_bytes())
            .map_err(|e| format!("write: {e}"))?;
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
        let answer: Answer =
            serde_json::from_slice(body).map_err(|e| fail(format!("answer: {e}")))?;
        answer
            .hits
            .into_iter()
            .map(|h| {
                if h.start > h.end || h.end > text.len() {
                    return Err(fail(format!("hit {}..{} outside the text", h.start, h.end)));
                }
                Ok(Hit {
                    rule: h.rule,
                    start: h.start,
                    end: h.end,
                    flag_only: false,
                })
            })
            .collect()
    }
}

/// Time left before `deadline`, or the timeout error.
fn remaining(deadline: Instant) -> Result<Duration, String> {
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() {
        return Err("timed out".into());
    }
    Ok(left)
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
        return Err(format!("status {status}"));
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
