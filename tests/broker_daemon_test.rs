//! #159 M7 — the daemon wires the broker prober to `/readyz`: a broker
//! whose probe fails is counted as down on a running `locksmithd`, while
//! readiness stays 200 and names no route.
//!
//! AGENT-325 — on the same daemon + CLI fixture, `agent set-credential
//! --stored-header-stdin` seals a per-agent value sent bare in a header.
//!
//! AGENT-381 — the CLI seals a header value with an inner space.

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
use wiremock::matchers::{header, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const SEALING_KEY: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";

fn set_key(f: &Fixture, route: &str, value: &str) {
    piped(f, &["tool", "set-key", route], value);
}

fn piped(f: &Fixture, args: &[&str], value: &str) {
    assert!(try_piped(f, args, value), "{} failed", args[1]);
}

fn set<'a>(id: &'a str, route: &'a str, extra: &[&'a str]) -> Vec<&'a str> {
    let mut args = vec!["agent", "set-credential", id, route];
    args.extend_from_slice(extra);
    args
}

fn try_piped(f: &Fixture, args: &[&str], value: &str) -> bool {
    run_piped(f, args, value).0 == Some(0)
}

/// Runs the CLI with `value` on stdin; returns its exit code and stderr.
/// As in `process::run`, stderr goes to a file, so a noisy child cannot
/// fill a pipe, and the guard kills a child that outlives the wait.
fn run_piped(f: &Fixture, args: &[&str], value: &str) -> (Option<i32>, String) {
    let stderr = tempfile::NamedTempFile::new().unwrap();
    let mut c = f.command(args);
    c.stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::from(stderr.reopen().unwrap()));
    let mut child = process::Guard(c.spawn().unwrap());
    child
        .0
        .stdin
        .take()
        .unwrap()
        .write_all(value.as_bytes())
        .unwrap();
    let status = process::wait(&mut child.0);
    (
        status.code(),
        std::fs::read_to_string(stderr.path()).unwrap(),
    )
}

/// Sealed values in the daemon's store, read beside it.
async fn sealed_count(f: &Fixture) -> i64 {
    use sqlx::Connection;
    let mut c = sqlx::SqliteConnection::connect_with(
        &sqlx::sqlite::SqliteConnectOptions::new()
            .filename(f.path().join("state.db"))
            .read_only(true),
    )
    .await
    .unwrap();
    let count = sqlx::query_scalar("SELECT COUNT(*) FROM credential_secrets")
        .fetch_one(&mut c)
        .await
        .unwrap();
    c.close().await.unwrap();
    count
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

    // Down takes the next probe (within the 5 s interval and a tick) and
    // two retries 10 s apart (AGENT-314): about 30 s, so allow 60.
    let deadline = Instant::now() + Duration::from_secs(60);
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

#[tokio::test]
async fn a_stored_header_from_stdin_is_sent_bare() {
    let upstream = MockServer::start().await;
    Mock::given(path("/inherited"))
        .and(header("x-api-key", "header-secret-1"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&upstream)
        .await;
    Mock::given(path("/named"))
        .and(header("authorization", "header-secret-2"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&upstream)
        .await;
    let mut f = Fixture::new();
    f.start_with_key(process::DAEMON, Some(SEALING_KEY)).await;
    for (route, auth) in [
        ("keyed", "header:X-Api-Key=UNSET_ENV"),
        ("named", "header:X-Api-Key=UNSET_ENV"),
        ("plain", "bearer=UNSET_ENV"),
    ] {
        f.op(&[
            "tool",
            "put",
            route,
            "--upstream",
            &upstream.uri(),
            "--auth",
            auth,
            "--egress",
            "direct",
        ]);
    }
    let a = f.op(&[
        "agent",
        "register",
        "--name",
        "hdr",
        "--allowlist",
        "keyed,named,plain",
    ]);
    let id = a["public_id"].as_str().unwrap();
    // An earlier bearer binding is replaced, and the route's own header
    // (X-Api-Key), not that binding, names where the value goes.
    piped(
        &f,
        &set(id, "keyed", &["--stored-bearer-stdin"]),
        "old-bearer",
    );
    piped(
        &f,
        &set(id, "keyed", &["--stored-header-stdin"]),
        "header-secret-1\n",
    );
    // --header overrides the route's header; the value still goes bare.
    piped(
        &f,
        &set(
            id,
            "named",
            &["--stored-header-stdin", "--header", "Authorization"],
        ),
        "header-secret-2",
    );
    // A route that names no header refuses, rather than sealing a bearer
    // (AGENT-328: for that reason, and with nothing sealed).
    let before = sealed_count(&f).await;
    let (code, err) = run_piped(&f, &set(id, "plain", &["--stored-header-stdin"]), "v");
    assert_eq!(
        code,
        Some(1),
        "a header route is needed without --header: {err}"
    );
    assert!(
        err.contains("400") && err.contains("invalid_stored_credential"),
        "{err}"
    );
    assert_eq!(sealed_count(&f).await, before, "a refusal seals nothing");
    let listed = f.op(&["agent", "credentials", "list", id]);
    assert!(
        !listed.to_string().contains("header-secret"),
        "value never listed"
    );
    let kinds: Vec<(String, String, String)> = listed
        .as_array()
        .unwrap()
        .iter()
        .map(|o| {
            let spec = &o["auth_spec"];
            let s = |k: &str| spec[k].as_str().unwrap_or("").to_owned();
            (
                o["registration"].as_str().unwrap().to_owned(),
                s("kind"),
                s("header"),
            )
        })
        .collect();
    let want = |r: &str, h: &str| (r.to_owned(), "stored_header".to_owned(), h.to_owned());
    assert!(kinds.contains(&want("keyed", "X-Api-Key")), "{kinds:?}");
    assert!(kinds.contains(&want("named", "Authorization")), "{kinds:?}");
    assert!(!kinds.iter().any(|k| k.0 == "plain"), "{kinds:?}");
    let token = a["token"].as_str().unwrap();
    for p in ["/api/keyed/inherited", "/api/named/named"] {
        let r = f
            .http
            .get(f.url(p))
            .bearer_auth(token)
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 200, "{p}");
    }
    f.stop();
}

/// AGENT-381 — a header value may hold an inner space (`Basic <b64>` for
/// git smart-HTTP). `tool set-key --header` and `agent set-credential
/// --stored-header-stdin` seal it and the upstream gets it intact; a
/// bearer still refuses one, an outer blank is refused, and nothing is
/// sealed for a refusal.
#[tokio::test]
async fn a_header_value_with_an_inner_space_is_sealed_intact() {
    let upstream = MockServer::start().await;
    for (p, v) in [
        ("/route", "Basic cm91dGU6a2V5"),
        ("/agent", "Basic YWdlbnQ6a2V5"),
    ] {
        Mock::given(path(p))
            .and(header("authorization", v))
            .respond_with(ResponseTemplate::new(200))
            .mount(&upstream)
            .await;
    }
    let mut f = Fixture::new();
    f.start_with_key(process::DAEMON, Some(SEALING_KEY)).await;
    let uri = upstream.uri();
    for (route, auth) in [
        ("git", "--broker"),
        ("own", "--auth=none"),
        ("plain", "--auth=none"),
    ] {
        f.op(&[
            "tool",
            "put",
            route,
            "--upstream",
            &uri,
            "--egress",
            "direct",
            auth,
        ]);
    }
    piped(
        &f,
        &["tool", "set-key", "git", "--header", "Authorization"],
        "Basic cm91dGU6a2V5\n",
    );
    let a = f.op(&[
        "agent",
        "register",
        "--name",
        "sp",
        "--allowlist",
        "git,own,plain",
    ]);
    let id = a["public_id"].as_str().unwrap();
    piped(&f, &set(id, "git", &["--broker"]), "");
    piped(
        &f,
        &set(
            id,
            "own",
            &["--stored-header-stdin", "--header", "Authorization"],
        ),
        "Basic YWdlbnQ6a2V5",
    );
    let token = a["token"].as_str().unwrap();
    for p in ["/api/git/route", "/api/own/agent"] {
        let r = f
            .http
            .get(f.url(p))
            .bearer_auth(token)
            .send()
            .await
            .unwrap();
        assert_eq!(
            r.status(),
            200,
            "{p}: the value reached the upstream intact"
        );
    }

    // A bearer holds no blank: the route that names no header refuses on
    // the daemon, the per-agent bearer in the CLI; an outer blank is
    // refused for a header too. None of them seals anything.
    let before = sealed_count(&f).await;
    let key = ["tool", "set-key", "git", "--header", "Authorization"];
    let usage = "visible ASCII";
    for (args, value, why) in [
        (
            vec!["tool", "set-key", "plain"],
            "Basic abc",
            "invalid_credential_value",
        ),
        (
            set(id, "plain", &["--stored-bearer-stdin"]),
            "Basic abc",
            "invalid native",
        ),
        (key.to_vec(), " Basic abc", usage),
        (key.to_vec(), "Basic abc ", usage),
        (
            set(id, "own", &["--stored-header-stdin"]),
            "Basic\u{7}abc",
            "invalid native",
        ),
    ] {
        let (code, err) = run_piped(&f, &args, value);
        assert_ne!(code, Some(0), "{args:?} {value:?} must be refused: {err}");
        assert!(err.contains(why), "{args:?} {value:?}: {err}");
        assert!(!err.contains("abc"), "the value is never echoed: {err}");
    }
    assert_eq!(sealed_count(&f).await, before, "a refusal seals nothing");
    f.stop();
}
