//! T7.3 — SizeCappedStream truncates at cap and emits marker.

use agent_locksmith::response_controls::{STREAM_TRUNCATION_MARKER, SizeCappedStream};
use bytes::Bytes;
use futures_util::stream::{self, StreamExt};
use std::sync::{Arc, Mutex};

fn fake_stream(
    chunks: Vec<&'static [u8]>,
) -> impl futures_util::Stream<Item = Result<Bytes, reqwest::Error>> {
    stream::iter(
        chunks
            .into_iter()
            .map(|c| Ok::<_, reqwest::Error>(Bytes::from_static(c))),
    )
}

#[tokio::test]
async fn passthrough_when_no_cap() {
    let upstream = fake_stream(vec![b"abc", b"def", b"ghi"]);
    let triggered: Arc<Mutex<Option<u64>>> = Arc::new(Mutex::new(None));
    let trig = triggered.clone();
    let mut wrapped = SizeCappedStream::new(upstream, None, move |n| {
        *trig.lock().unwrap() = Some(n);
    });

    let mut collected = Vec::new();
    while let Some(item) = wrapped.next().await {
        collected.extend_from_slice(&item.unwrap());
    }
    assert_eq!(collected, b"abcdefghi");
    assert!(triggered.lock().unwrap().is_none(), "no truncate fired");
}

#[tokio::test]
async fn under_cap_passes_unchanged() {
    let upstream = fake_stream(vec![b"hello", b"world"]);
    let mut wrapped = SizeCappedStream::new(upstream, Some(100), |_| {});
    let mut collected = Vec::new();
    while let Some(item) = wrapped.next().await {
        collected.extend_from_slice(&item.unwrap());
    }
    assert_eq!(collected, b"helloworld");
}

#[tokio::test]
async fn cap_truncates_mid_chunk_and_appends_marker() {
    let upstream = fake_stream(vec![b"AAAAA", b"BBBBB", b"CCCCC"]);
    let triggered: Arc<Mutex<Option<u64>>> = Arc::new(Mutex::new(None));
    let trig = triggered.clone();
    let mut wrapped = SizeCappedStream::new(upstream, Some(7), move |n| {
        *trig.lock().unwrap() = Some(n);
    });

    let mut collected = Vec::new();
    while let Some(item) = wrapped.next().await {
        collected.extend_from_slice(&item.unwrap());
    }
    let s = String::from_utf8(collected).unwrap();
    // 5 As + 2 Bs = 7 bytes prefix, then marker.
    assert!(s.starts_with("AAAAABB"), "prefix: {s}");
    assert!(
        s.contains(STREAM_TRUNCATION_MARKER),
        "marker in output: {s}"
    );
    // Truncate callback fires with the cap as the byte count.
    assert_eq!(*triggered.lock().unwrap(), Some(7));
    // The third chunk (CCCCC) never reaches the consumer.
    assert!(!s.contains('C'));
}

#[tokio::test]
async fn cap_at_exact_chunk_boundary_still_works() {
    let upstream = fake_stream(vec![b"AAAAA", b"BBBBB"]);
    let mut wrapped = SizeCappedStream::new(upstream, Some(5), |_| {});
    let mut collected = Vec::new();
    while let Some(item) = wrapped.next().await {
        collected.extend_from_slice(&item.unwrap());
    }
    let s = String::from_utf8(collected).unwrap();
    assert!(s.starts_with("AAAAA"));
    assert!(s.contains(STREAM_TRUNCATION_MARKER));
    assert!(!s.contains('B'));
}
