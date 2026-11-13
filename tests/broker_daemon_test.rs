//! #159 M7 — the daemon wires the broker prober to `/readyz`: a broker
//! whose probe fails is counted as down on a running `locksmithd`, while
//! readiness stays 200 and names no route.

#![allow(dead_code)]
#[path = "native_process/fixture.rs"]
mod fixture;
#[path = "native_process/observations.rs"]
mod observations;
#[path = "native_process/pki.rs"]
mod pki;
#[path = "explicit_binding_smoke/process.rs"]
mod process;

use fixture::Fixture;
use serde_json::Value;
use std::io::Write;
use std::process::Stdio;
use std::time::{Duration, Instant};
use wiremock::matchers::path;
use wiremock::{Mock, MockServer, ResponseTemplate};

const SEALING_KEY: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";

fn set_key(f: &Fixture, route: &str, value: &str) {
    let mut c = f.command(&["tool", "set-key", route]);
    c.stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut child = c.spawn().unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(value.as_bytes())
        .unwrap();
    assert!(process::wait(&mut child).success(), "set-key failed");
}

#[tokio::test]
async fn readyz_counts_a_down_broker() {
    let broker = MockServer::start().await;
    Mock::given(path("/healthz"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&broker)
        .await;
    let mut f = Fixture::new();
    f.start_with_key(process::DAEMON, Some(SEALING_KEY)).await;
    f.op(&[
        "tool",
        "put",
        "pool",
        "--upstream",
        &broker.uri(),
        "--auth",
        "none",
        "--egress",
        "direct",
        "--broker",
        "--health-path",
        "/healthz",
        "--health-interval",
        "5",
    ]);
    set_key(&f, "pool", "daemon-broker-key");

    // The prober ticks every 5 s; allow a few ticks.
    let deadline = Instant::now() + Duration::from_secs(30);
    let ready = loop {
        let r = f.http.get(f.url("/readyz")).send().await.unwrap();
        assert_eq!(r.status(), 200, "a down broker never fails readiness");
        let text = r.text().await.unwrap();
        let v: Value = serde_json::from_str(&text).unwrap();
        if v["brokers"]["down"] == 1 {
            break text;
        }
        assert!(
            Instant::now() < deadline,
            "broker never counted down: {text}"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    };
    assert!(!ready.contains("pool"), "readyz names no route: {ready}");
    let probes = broker.received_requests().await.unwrap();
    assert!(probes.iter().any(|r| r.url.path() == "/healthz"));
    f.stop();
}
