//! Actual shipping CLI/daemon controlled TLS journey, reusing consent custody setup.
use super::*;
fn input(properties: Value, required: Value) -> Value {
    json!({"type":"object","properties":properties,"required":required,"additionalProperties":false})
}
fn manifest() -> Value {
    json!({"tools":[
        {"name":"get_workspace","inputSchema":input(json!({}),json!([]))},
        {"name":"get_user","inputSchema":input(json!({"query":{"type":"string","const":"me"}}),json!(["query"]))},
        {"name":"read_record","inputSchema":input(json!({"ticket":{"type":"string","const":"CASE-206"}}),json!(["ticket"]))}
    ]})
}
async fn selection(f: &Fixture, agent: &str, label: &str) -> Value {
    let v = f.op(&["oauth", "account-status", "fixture", "--label", label]);
    f.op(&[
        "agent",
        "select-oauth",
        agent,
        "fixture",
        "--label",
        label,
        "--if-match",
        v["revision"].as_str().unwrap(),
    ])
}
async fn prepare(f: &Fixture, agent: &str) {
    let path = format!("/admin/operator/tools/fixture/mcp/observations/{agent}");
    let (status, before) = request(f, "GET", &path, None).await;
    assert_eq!(status, 200);
    let (status, state) = request(
        f,
        "POST",
        &path,
        Some(json!({"source":before["source"],"generation":before["observation"]["generation"]})),
    )
    .await;
    assert_eq!(status, 200, "{state}");
    let tool = state["observation"]["manifest"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["tool"]["name"] == "read_record")
        .unwrap();
    let(status,review)=request(f,"PUT",&format!("/admin/operator/tools/fixture/mcp/reviews/{agent}"),Some(json!({"source":state["source"],"generation":state["observation"]["generation"],"name":"read_record","observed_digest":tool["observed_digest"],"effect":"read"}))).await;
    assert_eq!(status, 200, "{review}");
    let(status,v)=request(f,"PUT",&format!("/admin/operator/agents/{agent}/mcp-grants/fixture"),Some(json!({"source":state["source"],"generation":state["observation"]["generation"],"revision":state["grant_revision"],"tools":[{"name":"read_record","contract_digest":review["contract_digest"]}]}))).await;
    assert_eq!(status, 200, "{v}");
}
async fn rpc(
    f: &Fixture,
    agent: &Value,
    path: &str,
    session: Option<&str>,
    body: Value,
) -> (u16, Value, Option<String>) {
    let mut r = f
        .http
        .post(f.url(path))
        .bearer_auth(agent["token"].as_str().unwrap())
        .header("accept", "application/json, text/event-stream")
        .header("mcp-protocol-version", "2025-11-25")
        .json(&body);
    if let Some(s) = session {
        r = r.header("mcp-session-id", s);
    }
    let r = r.send().await.unwrap();
    let status = r.status().as_u16();
    let session = r
        .headers()
        .get("mcp-session-id")
        .map(|s| s.to_str().unwrap().to_string());
    let text = r.text().await.unwrap();
    let value = if text.is_empty() {
        Value::Null
    } else if text.contains("data: ") {
        serde_json::from_str(text.lines().find_map(|l| l.strip_prefix("data: ")).unwrap()).unwrap()
    } else {
        serde_json::from_str(&text).unwrap()
    };
    (status, value, session)
}
async fn open(f: &Fixture, agent: &Value, compact: bool) -> (String, String) {
    let path = if compact {
        "/mcp/fixture/compact"
    } else {
        "/mcp/fixture"
    };
    let(status,v,session)=rpc(f,agent,path,None,json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"controlled206","version":"1"}}})).await;
    assert_eq!(status, 200, "{v}");
    let session = session.unwrap();
    assert_eq!(
        rpc(
            f,
            agent,
            path,
            Some(&session),
            json!({"jsonrpc":"2.0","method":"notifications/initialized"})
        )
        .await
        .0,
        202
    );
    assert_eq!(
        rpc(
            f,
            agent,
            path,
            Some(&session),
            json!({"jsonrpc":"2.0","id":2,"method":"tools/list"})
        )
        .await
        .0,
        200
    );
    (path.into(), session)
}
async fn invoke(f: &Fixture, agent: &Value, compact: bool, account: &str) {
    let (path, session) = open(f, agent, compact).await;
    let args = if compact {
        let(_,search,_)=rpc(f,agent,&path,Some(&session),json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"search","arguments":{"query":"read_record","limit":8}}})).await;
        let text = search["result"]["content"][0]["text"].as_str().unwrap();
        let result: Value = serde_json::from_str(text).unwrap();
        let handle = result["matches"][0]["handle"].clone();
        let(_,described,_)=rpc(f,agent,&path,Some(&session),json!({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"describe","arguments":{"handle":handle}}})).await;
        assert!(described.get("result").is_some(), "{described}");
        json!({"name":"invoke","arguments":{"handle":handle,"contract_digest":result["matches"][0]["contract_digest"],"arguments":{"ticket":"CASE-206"}}})
    } else {
        json!({"name":"read_record","arguments":{"ticket":"CASE-206"}})
    };
    let (status, v, _) = rpc(
        f,
        agent,
        &path,
        Some(&session),
        json!({"jsonrpc":"2.0","id":5,"method":"tools/call","params":args}),
    )
    .await;
    assert_eq!(status, 200);
    assert!(v["result"].is_object(), "{v}");
    assert_ne!(v["result"]["isError"], true);
    let result: Value =
        serde_json::from_str(v["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(result["account"], account);
    assert!(
        f.http
            .delete(f.url(&path))
            .bearer_auth(agent["token"].as_str().unwrap())
            .header("mcp-session-id", session)
            .header("mcp-protocol-version", "2025-11-25")
            .send()
            .await
            .unwrap()
            .status()
            .is_success()
    );
}
pub async fn journey() {
    let mut f = Fixture::new();
    std::fs::write(f.path().join("refresh-enabled"), "fixture").unwrap();
    std::fs::write(
        f.path().join("native-manifest.json"),
        manifest().to_string(),
    )
    .unwrap();
    let t = Twin::start(&f);
    let port = configure(&f, &t);
    start(&mut f).await;
    native_registration(&f, &t, port).await;
    let created = connect(&f, "native");
    assert_eq!(
        f.http
            .get(callback(&t, port, &created))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    let mut agents = Vec::new();
    for name in ["native-x", "native-shared-x"] {
        let a = f.op(&[
            "agent",
            "register",
            "--name",
            name,
            "--allowlist",
            "fixture",
        ]);
        selection(&f, a["public_id"].as_str().unwrap(), "native").await;
        prepare(&f, a["public_id"].as_str().unwrap()).await;
        agents.push(a);
    }
    for a in &agents {
        for compact in [false, true] {
            invoke(&f, a, compact, "X").await;
        }
    }
    assert_eq!(counts(&f)["tool"], 4);
    std::fs::write(f.path().join("native-y"), "fixture").unwrap();
    let y_consent = connect(&f, "native-y");
    assert_eq!(
        f.http
            .get(callback(&t, port, &y_consent))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    let y = f.op(&[
        "agent",
        "register",
        "--name",
        "native-y",
        "--allowlist",
        "fixture",
    ]);
    selection(&f, y["public_id"].as_str().unwrap(), "native-y").await;
    prepare(&f, y["public_id"].as_str().unwrap()).await;
    for compact in [false, true] {
        invoke(&f, &y, compact, "Y").await;
    }
    assert_eq!(counts(&f)["tool"], 6);
    let (path, session) = open(&f, &agents[0], false).await;
    let old = f.op(&["oauth", "account-status", "fixture", "--label", "native"]);
    f.op(&[
        "oauth",
        "refresh",
        "fixture",
        "--label",
        "native",
        "--if-match",
        old["revision"].as_str().unwrap(),
    ]);
    let (status, _, _) = rpc(
        &f,
        &agents[0],
        &path,
        Some(&session),
        json!({"jsonrpc":"2.0","id":9,"method":"tools/list"}),
    )
    .await;
    assert_eq!(status, 404);
    assert_eq!(counts(&f)["tool"], 6);
    for a in &agents {
        prepare(&f, a["public_id"].as_str().unwrap()).await;
        for compact in [false, true] {
            invoke(&f, a, compact, "X").await;
        }
    }
    for compact in [false, true] {
        invoke(&f, &y, compact, "Y").await;
    }
    assert_eq!(counts(&f)["tool"], 12);
    let v = f.op(&["oauth", "account-status", "fixture", "--label", "native"]);
    f.op(&[
        "oauth",
        "disconnect",
        "fixture",
        "--label",
        "native",
        "--if-match",
        v["revision"].as_str().unwrap(),
    ]);
    for a in &agents {
        assert_eq!(
            f.op(&[
                "agent",
                "credentials",
                "list",
                a["public_id"].as_str().unwrap()
            ]),
            json!([])
        );
    }
    assert_eq!(
        f.op(&[
            "agent",
            "credentials",
            "list",
            y["public_id"].as_str().unwrap()
        ])
        .as_array()
        .unwrap()
        .len(),
        1
    );
    println!(
        "controlled native TLS: X/shared X/Y, standard/compact,12 effects with pre-effect committed audit, refresh/new-session repair and disconnect isolation; arrivals={}",
        counts(&f)
    );
    f.stop();
    t.stop();
}

pub async fn races() {
    for mode in ["refresh", "disconnect", "expiry", "audit", "commit"] {
        let mut f = Fixture::new();
        std::fs::write(f.path().join("refresh-enabled"), "fixture").unwrap();
        std::fs::write(
            f.path().join("native-manifest.json"),
            manifest().to_string(),
        )
        .unwrap();
        let t = Twin::start(&f);
        let port = configure(&f, &t);
        start(&mut f).await;
        native_registration(&f, &t, port).await;
        let created = connect(&f, "native");
        assert_eq!(
            f.http
                .get(callback(&t, port, &created))
                .send()
                .await
                .unwrap()
                .status(),
            200
        );
        let a = f.op(&[
            "agent",
            "register",
            "--name",
            "native-race",
            "--allowlist",
            "fixture",
        ]);
        selection(&f, a["public_id"].as_str().unwrap(), "native").await;
        prepare(&f, a["public_id"].as_str().unwrap()).await;
        let (path, session) = open(&f, &a, false).await;
        std::fs::write(f.path().join("hold-native-init"), "fixture").unwrap();
        let request=f.http.post(f.url(&path)).bearer_auth(a["token"].as_str().unwrap()).header("accept","application/json, text/event-stream").header("mcp-protocol-version","2025-11-25").header("mcp-session-id",&session).json(&json!({"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"read_record","arguments":{"ticket":"CASE-206"}}}));
        let pending =
            tokio::spawn(async move { request.send().await.unwrap().text().await.unwrap() });
        arrived(&f, "native-init").await;
        let pool =
            sqlx::SqlitePool::connect(&format!("sqlite://{}", f.path().join("state.db").display()))
                .await
                .unwrap();
        if mode == "expiry" {
            sqlx::query(
                "UPDATE oauth_sessions SET access_token_expires_at=1 WHERE session_label='native'",
            )
            .execute(&pool)
            .await
            .unwrap();
        } else if mode == "audit" {
            sqlx::raw_sql("CREATE TRIGGER reject_native_audit BEFORE INSERT ON audit WHEN NEW.event='mcp_admitted' BEGIN SELECT RAISE(ABORT,'fixture'); END;").execute(&pool).await.unwrap();
        } else if mode == "commit" {
            sqlx::raw_sql("CREATE TABLE parent_guard(id INTEGER PRIMARY KEY); CREATE TABLE deferred_guard(id INTEGER REFERENCES parent_guard(id) DEFERRABLE INITIALLY DEFERRED); CREATE TRIGGER reject_native_commit AFTER INSERT ON audit WHEN NEW.event='mcp_admitted' BEGIN INSERT INTO deferred_guard VALUES(1); END;").execute(&pool).await.unwrap();
        } else {
            let v = f.op(&["oauth", "account-status", "fixture", "--label", "native"]);
            f.op(&[
                "oauth",
                mode,
                "fixture",
                "--label",
                "native",
                "--if-match",
                v["revision"].as_str().unwrap(),
            ]);
        }
        std::fs::write(f.path().join("release-native-init"), "fixture").unwrap();
        let body = tokio::time::timeout(Duration::from_secs(8), pending)
            .await
            .unwrap()
            .unwrap();
        assert!(!body.contains("CASE-206"), "no successful tool result");
        if mode == "audit" {
            assert!(body.contains("admission_audit_failed"));
        }
        if mode == "commit" {
            assert!(body.contains("admission_commit_failed"));
        }
        let admissions: i64 =
            sqlx::query_scalar("SELECT count(*) FROM audit WHERE event='mcp_admitted'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(admissions, 0);
        assert_eq!(counts(&f).get("tool"), None);
        pool.close().await;
        f.stop();
        t.stop();
        println!(
            "controlled native held initialization {mode}: zero committed admissions / zero TOOL; joined"
        );
    }
}

async fn native_registration(f: &Fixture, t: &Twin, port: u16) {
    if std::env::var_os("LOCKSMITH_TEST_DEFINITION_ACTIVATION").is_none() {
        let auth = registration(f, t, port).await;
        assert_eq!(request(f,"PUT","/admin/operator/tools/fixture",Some(json!({"upstream":t.url("/mcp/readonly"),"auth":auth,"egress":"direct","protocol":"mcp_streamable_http","mcp":{"protocol_version":"2025-11-25","allow_private_destination":true,"compact":true}}))).await.0,200);
        return;
    }
    let path = f.path().join("definition.json");
    std::fs::write(
        &path,
        include_str!("../../definitions/customer-controlled.example.json"),
    )
    .unwrap();
    f.op(&["integration", "import", "--file", path.to_str().unwrap()]);
    f.op(&[
        "tool",
        "from-definition",
        "fixture",
        "--definition",
        "local.customer-controlled",
        "--revision",
        "1",
        "--auth-profile",
        "controlled",
        "--upstream",
        &t.url("/mcp/readonly"),
        "--allow-private-destination",
    ]);
    let v = f.op(&["tool", "get", "fixture"]);
    f.op(&[
        "tool",
        "activate-definition",
        "fixture",
        "--if-match",
        v["definition_control"]["revision"].as_str().unwrap(),
        "--compact",
        "--oauth-profile",
        "fixture",
    ]);
    assert!(
        !f.path().join("counts.json").exists(),
        "activation must cause zero provider arrivals"
    );
}
