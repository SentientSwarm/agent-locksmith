//! Setup-only reuse of the existing Rust and Python SDK assertions.
use super::{fixture::Fixture, process, receiver, sdk, support as s};
use serde_json::{Value, json};
const KEY: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
fn create(f: &Fixture, mechanism: &str, endpoint: &str) {
    let mut d: Value =
        serde_json::from_str(include_str!("../../definitions/customer.example.json")).unwrap();
    d["auth_profiles"][0]["mechanism"] = json!(mechanism);
    d["auth_profiles"][0]["required_scopes"] = if mechanism == "oauth_provider" {
        json!(["read"])
    } else {
        json!([])
    };
    let path = f.path().join("customer.json");
    std::fs::write(&path, d.to_string()).unwrap();
    f.op(&["integration", "import", "--file", path.to_str().unwrap()]);
    f.op(&[
        "tool",
        "from-definition",
        "native",
        "--definition",
        "local.customer",
        "--revision",
        "1",
        "--auth-profile",
        "none",
        "--upstream",
        endpoint,
        "--allow-private-destination",
    ]);
    let state = f.op(&["tool", "get", "native"]);
    let mut args = vec![
        "tool",
        "activate-definition",
        "native",
        "--if-match",
        state["definition_control"]["revision"].as_str().unwrap(),
        "--compact",
    ];
    if mechanism == "oauth_provider" {
        args.extend(["--oauth-profile", "controlled"]);
    }
    let active = f.op(&args);
    assert_eq!(active["activation"], "active");
    assert_eq!(active["mcp"]["definition"], state["mcp"]["definition"]);
    assert!(s::effects(f).is_empty());
}
fn agent(f: &Fixture, name: &str) -> Value {
    f.op(&["agent", "register", "--name", name, "--allowlist", "native"])
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pinned_customer_both_sdks_none_and_bearer_x_shared_x_y() {
    std::env::var("LOCKSMITH_NATIVE_PYTHON")
        .expect("current pinned SDK proof requires existing Python SDK");
    for mechanism in ["none", "bearer"] {
        let mut f = Fixture::new();
        receiver::configure(&f);
        s::manifest(&f);
        let up = receiver::Receiver::start(&f);
        f.start_with_key(process::DAEMON, Some(KEY)).await;
        create(&f, mechanism, &format!("https://localhost:{}/mcp", up.port));
        let a = agent(&f, "customer-a");
        let id = a["public_id"].as_str().unwrap();
        if mechanism == "none" {
            f.op(&["agent", "set-credential", id, "native", "--no-auth"]);
            sdk::exercise(&f, &a, "None", true).await;
        } else {
            let b = agent(&f, "customer-b");
            let reference = s::stored(&f, id, "fixture-account-x");
            f.op(&[
                "agent",
                "set-credential",
                b["public_id"].as_str().unwrap(),
                "native",
                "--stored-bearer-ref",
                &reference,
            ]);
            sdk::exercise(&f, &a, "X", false).await;
            s::stored(&f, id, "fixture-account-y");
            sdk::exercise(&f, &b, "X", false).await;
            sdk::exercise(&f, &a, "Y", false).await;
        }
        let effects = s::effects(&f);
        let expected = if mechanism == "none" {
            vec!["None"]
        } else {
            vec!["X", "X", "Y"]
        };
        assert_eq!(effects.len(), expected.len() * 4);
        for (n, e) in effects.iter().enumerate() {
            assert_eq!(e["account"], expected[n / 4]);
            assert_eq!(e["arguments"], json!({"workspace":"fixed","key":"record"}));
            assert_eq!(e["committed"], n + 1);
        }
        f.stop();
        up.stop();
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pinned_controlled_customer_both_sdks_access_only() {
    use agent_locksmith::oauth::{SealingKey, consent::config::Profile};
    std::env::var("LOCKSMITH_NATIVE_PYTHON")
        .expect("current pinned SDK proof requires existing Python SDK");
    let mut f = Fixture::new();
    receiver::configure(&f);
    s::manifest(&f);
    let up = receiver::Receiver::start(&f);
    let issuer = format!("https://127.0.0.1:{}", up.port);
    let callback = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let profile = json!({"id":"controlled","kind":"controlled-linear-v1","client_id":"fixture","client_generation":1,"issuer":issuer,"authorization_endpoint":format!("{issuer}/authorize"),"token_endpoint":format!("{issuer}/token"),"resource":format!("{issuer}/mcp/readonly"),"redirect_profile_id":"local","redirect_uri":format!("https://127.0.0.1:{callback}/oauth/callback"),"expected_workspace":"00000000-0000-0000-0000-000000000041","expected_user":"00000000-0000-0000-0000-000000000042","ca_path":f.path().join("ca.pem")});
    let p: Profile = serde_json::from_value(profile.clone()).unwrap();
    let config = f.path().join("config.yaml");
    let mut c: Value = serde_json::from_slice(&std::fs::read(&config).unwrap()).unwrap();
    c["oauth_consent"] = json!({"callback":{"address":format!("127.0.0.1:{callback}"),"cert_path":f.path().join("server.pem"),"key_path":f.path().join("server.key")},"profiles":[profile]});
    std::fs::write(config, c.to_string()).unwrap();
    f.start_with_keys(process::DAEMON, None, Some(KEY)).await;
    create(&f, "oauth_provider", &p.resource);
    let operators: Value =
        serde_yaml::from_slice(&std::fs::read(f.path().join("operators.yaml")).unwrap()).unwrap();
    let owner = operators["operators"][0]["public_id"].as_str().unwrap();
    // Synthetic pre-sealed account setup, explicitly not a provider consent claim.
    let pool = s::pool(&f).await;
    let key = SealingKey::from_b64(KEY).unwrap();
    let (ct, n) = key.seal(b"fixture-account-x").unwrap();
    sqlx::query("INSERT INTO oauth_sessions(name,session_label,kind,owner_id,profile_id,profile_digest,workspace_id,user_id,access_token_ciphertext,access_token_nonce,created_at,updated_at) VALUES('native','sdk','controlled_linear_v1',?,?,?,?,?,?,?,1,1)").bind(owner).bind(&p.id).bind(p.digest().unwrap()).bind(&p.expected_workspace).bind(&p.expected_user).bind(ct).bind(n).execute(&pool).await.unwrap();
    pool.close().await;
    let a = agent(&f, "controlled-customer");
    let view = f.op(&["oauth", "account-status", "native", "--label", "sdk"]);
    f.op(&[
        "agent",
        "select-oauth",
        a["public_id"].as_str().unwrap(),
        "native",
        "--label",
        "sdk",
        "--if-match",
        view["revision"].as_str().unwrap(),
    ]);
    sdk::exercise(&f, &a, "X", false).await;
    assert_eq!(s::effects(&f).len(), 4);
    f.stop();
    up.stop();
}
