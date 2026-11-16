//! AGENT-259 — a route Locksmith sends without a proxy goes straight to its
//! upstream. reqwest otherwise honours `HTTP(S)_PROXY` / `ALL_PROXY` from
//! the daemon's environment, which would hand `direct` and `external`
//! traffic, credentials included, to a proxy no route names.
//!
//! A standalone binary with one test, because it sets process environment.

use agent_locksmith::client_pool::ClientPool;
use agent_locksmith::config::{EgressMode, ToolTimeouts, parse_config_str};
use wiremock::matchers::any;
use wiremock::{Mock, MockServer, ResponseTemplate};

const PROXY_VARS: [&str; 6] = [
    "HTTP_PROXY",
    "http_proxy",
    "HTTPS_PROXY",
    "https_proxy",
    "ALL_PROXY",
    "all_proxy",
];

#[tokio::test]
async fn routes_without_a_configured_proxy_ignore_proxy_env() {
    let env_proxy = MockServer::start().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(502))
        .mount(&env_proxy)
        .await;
    let upstream = MockServer::start().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(200))
        .mount(&upstream)
        .await;
    // SAFETY: this binary has one test and nothing else reads the
    // environment while it is written.
    unsafe {
        for var in PROXY_VARS {
            std::env::set_var(var, env_proxy.uri());
        }
        std::env::remove_var("NO_PROXY");
        std::env::remove_var("no_proxy");
    }

    let timeouts = ToolTimeouts {
        request_seconds: 5,
        idle_seconds: 5,
    };
    let cases = [
        ("direct", EgressMode::Direct, ""),
        (
            "external",
            EgressMode::Proxied,
            "egress:\n  mode: external\n",
        ),
    ];
    for (name, egress, extra) in cases {
        let config = parse_config_str(&format!(
            "listen:\n  host: \"127.0.0.1\"\n  port: 9200\n{extra}tools: []\n"
        ))
        .unwrap();
        let client = ClientPool::new()
            .get_or_build_for(name, timeouts, egress, None, &config)
            .unwrap();
        let resp = client
            .get(format!("{}/v1", upstream.uri()))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200, "{name} route used the env proxy");
    }
    // AGENT-277 — clients outside the route pool too: CRL fetches.
    let crl = agent_locksmith::mtls::crl::fetch_client(&[]);
    let resp = crl
        .get(format!("{}/crl.pem", upstream.uri()))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "the CRL client used the env proxy");
    let leaked = env_proxy.received_requests().await.unwrap();
    assert!(
        leaked.is_empty(),
        "{} requests reached the env proxy",
        leaked.len()
    );
}
