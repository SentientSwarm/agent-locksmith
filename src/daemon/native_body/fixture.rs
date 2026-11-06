use crate::{config::parse_config_str, native_authority::body_probe};
use std::{sync::Arc, time::Duration};
use tokio::task::JoinHandle;
#[allow(dead_code)] // Existing shared PKI also produces an unused client identity.
#[path = "../../../tests/native_process/pki.rs"]
mod pki;

pub struct Fixture {
    pub dir: tempfile::TempDir,
    pub key: String,
    pub probe: Arc<body_probe::Probe>,
    pub hold_key: String,
    pub held: Arc<body_probe::Probe>,
    pub token: String,
    pub config: Option<crate::config::AppConfig>,
    pub client: reqwest::Client,
    pub url: String,
}
impl Fixture {
    pub fn new(tls: bool) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("admin.sock");
        let key = format!("{}:body", socket.display());
        let hold_key = format!("{}:{}", socket.display(), if tls { "https" } else { "uds" });
        let token = operator(dir.path());
        let (client, url, https) = client_config(dir.path(), &socket, tls);
        let yaml = format!(
            "listen:\n  host: 127.0.0.1\n  port: 0\n  admin_socket:\n    path: {}\n{}database:\n  path: {}\noperator_credentials_path: {}\ntools: []\n",
            socket.display(),
            https,
            dir.path().join("state.db").display(),
            dir.path().join("operators.yaml").display()
        );
        Self {
            config: Some(parse_config_str(&yaml).unwrap()),
            probe: body_probe::register(&key),
            held: body_probe::register(&hold_key),
            dir,
            key,
            hold_key,
            token,
            client,
            url,
        }
    }
    pub async fn ready(&self) -> bool {
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                if self
                    .client
                    .get(format!("{}/admin/operator/agents", self.url))
                    .bearer_auth(&self.token)
                    .send()
                    .await
                    .is_ok_and(|r| r.status().is_success())
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .is_ok()
    }
    pub fn request(
        &self,
        path: &str,
        method: &str,
    ) -> (
        JoinHandle<reqwest::Result<reqwest::Response>>,
        tokio::sync::mpsc::Sender<Result<bytes::Bytes, std::io::Error>>,
    ) {
        let (send, mut receive) = tokio::sync::mpsc::channel(1);
        let stream = futures_util::stream::poll_fn(move |cx| receive.poll_recv(cx));
        let request = self
            .client
            .request(method.parse().unwrap(), format!("{}{path}", self.url))
            .bearer_auth(&self.token)
            .header("content-type", "application/json")
            .header("x-native-body-test", &self.key)
            .body(reqwest::Body::wrap_stream(stream));
        (tokio::spawn(request.send()), send)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        body_probe::remove(&self.key);
        body_probe::remove(&self.hold_key);
    }
}
fn operator(dir: &std::path::Path) -> String {
    let token = crate::token::StructuredToken::generate(crate::token::TokenNamespace::Operator);
    let hash = crate::argon2_helper::hash(&secrecy::SecretString::from(
        token.secret.expose().to_string(),
    ))
    .unwrap();
    std::fs::write(
        dir.join("operators.yaml"),
        format!(
            "operators:\n  - name: body-owner\n    public_id: {}\n    token_hash: {}\n",
            token.public_id.as_str(),
            hash
        ),
    )
    .unwrap();
    token.wire_format()
}
fn client_config(
    dir: &std::path::Path,
    socket: &std::path::Path,
    tls: bool,
) -> (reqwest::Client, String, String) {
    let builder = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(30));
    if !tls {
        return (
            builder.unix_socket(socket).build().unwrap(),
            "http://localhost".into(),
            String::new(),
        );
    }
    tls_client(dir, builder)
}
fn tls_client(
    dir: &std::path::Path,
    builder: reqwest::ClientBuilder,
) -> (reqwest::Client, String, String) {
    crate::admin::https::install_crypto_provider_once();
    let pki = pki::Pki::write(dir);
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let client = builder
        .add_root_certificate(reqwest::Certificate::from_pem(pki.ca.as_bytes()).unwrap())
        .build()
        .unwrap();
    let https = format!(
        "  admin_https:\n    enabled: true\n    host: 127.0.0.1\n    port: {port}\n    cert_path: {}\n    key_path: {}\n",
        dir.join("server.pem").display(),
        dir.join("server.key").display()
    );
    (client, format!("https://localhost:{port}"), https)
}
