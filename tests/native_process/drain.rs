use super::{fixture::Fixture, process, wire};
use serde_json::{Value, json};

pub async fn exercise() {
    let mut f = Fixture::new();
    let path = f.path().join("config.yaml");
    let mut config: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    config["mcp"] = json!({"sessions":1});
    std::fs::write(&path, config.to_string()).unwrap();
    f.start(process::DAEMON).await;
    second_daemon_refused(&f, &config).await;
    let agent = f.enroll("caller", "https://example.com/mcp");
    let token = agent["token"].as_str().unwrap();
    let id = wire::open(&f, token).await;
    let refused = wire::post(&f, token, None, wire::init()).await;
    assert_eq!(refused.status(), 429);
    assert_eq!(refused.headers()["retry-after"], "1");
    let response = wire::get(&f, token, &id).await;
    let stalled_tls = std::net::TcpStream::connect(("127.0.0.1", f.port)).unwrap();
    f.stop();
    drop(stalled_tls);
    drop(response);
    assert!(std::net::TcpStream::connect(("127.0.0.1", f.port)).is_err());
    restart(&mut f, token, &id).await;
}
async fn second_daemon_refused(f: &Fixture, config: &Value) {
    let mut second = config.clone();
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    second["database"]["path"] = "./state.db".into();
    second["listen"]["port"] = port.into();
    second["listen"]["admin_socket"]["path"] =
        f.path().join("second.sock").to_str().unwrap().into();
    std::fs::write(f.path().join("second.yaml"), second.to_string()).unwrap();
    let mut c = process::command(process::DAEMON);
    c.current_dir(f.path()).args(["--config", "second.yaml"]);
    let output = process::run(c);
    assert!(!output.status.success());
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(text.contains("database already owned"));
    assert!(!f.path().join("second.sock").exists());
    assert!(std::net::TcpStream::connect(("127.0.0.1", port)).is_err());
    assert_eq!(
        f.http.get(f.url("/livez")).send().await.unwrap().status(),
        200
    );
}

async fn restart(f: &mut Fixture, token: &str, id: &str) {
    f.start(process::DAEMON).await;
    let r = wire::post(
        f,
        token,
        Some(id),
        json!({"jsonrpc":"2.0","id":1,"method":"ping"}),
    )
    .await;
    assert_eq!(
        r.status(),
        404,
        "session IDs survive neither process nor state restart"
    );
    let _ = wire::open(f, token).await;
    f.stop();
}
