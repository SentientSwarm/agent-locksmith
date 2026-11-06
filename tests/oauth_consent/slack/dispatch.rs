use super::*;

async fn prepared() -> (Fixture, Twin, Value) {
    let (mut f, t) = failures::ready().await;
    f.http = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(30))
        .add_root_certificate(reqwest::Certificate::from_pem(f.pki.ca.as_bytes()).unwrap())
        .build()
        .unwrap();
    let created = setup::connect_slack(&f, "reader");
    assert_eq!(setup::authorize(&f, &created, false).await, 200);
    let agent = f.op(&[
        "agent",
        "register",
        "--name",
        "delayed-call",
        "--allowlist",
        "fixture",
    ]);
    receiving::select(&f, &agent);
    receiving::prepare(&f, &agent).await;
    (f, t, agent)
}

pub async fn deadlines() {
    for mode in ["headers", "body", "sse"] {
        for compact in [false, true] {
            delayed(mode, compact).await;
        }
    }
}

async fn params(f: &Fixture, agent: &Value, path: &str, session: &str, compact: bool) -> Value {
    if compact {
        receiving::compact_params(f, agent, path, session, "search_messages", 0).await
    } else {
        json!({"name":"search_messages","arguments":{"channel":"CPUBLIC1"}})
    }
}

async fn delayed(mode: &str, compact: bool) {
    let (mut f, t, agent) = prepared().await;
    let (path, session) = native::open(&f, &agent, compact).await;
    let params = params(&f, &agent, &path, &session, compact).await;
    failures::fault(&f, "native-call", mode, 11);
    let start = Instant::now();
    let (status, result, _) = native::rpc(
        &f,
        &agent,
        &path,
        Some(&session),
        json!({"jsonrpc":"2.0","id":5,"method":"tools/call","params":params}),
    )
    .await;
    assert!(
        status != 200 || result.get("error").is_some() || result["result"]["isError"] == true,
        "{result}"
    );
    assert!(start.elapsed() >= Duration::from_secs(9));
    assert_eq!(counts(&f)["tool"], 1, "one admitted effect, no retry");
    assert_eq!(counts(&f)["native-call"], 1);
    f.stop();
    t.stop();
    println!(
        "native dispatch {mode} compact={compact}: bounded refusal, one already admitted effect, joined"
    );
}
