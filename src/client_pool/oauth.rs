//! AGENT-269 — clients for OAuth token calls: bootstrap exchange, refresh
//! and device login. A token call takes the egress decision of the route
//! it serves, so a `proxied` route's token endpoint goes through
//! `egress_proxy` under `pipelock`, directly under `external`, and nowhere
//! when nothing enforces egress. Config is read once, so both clients are
//! built once at startup.

use super::{
    ClientUnavailable, add_ca_bundle, egress_proxy, finish, no_redirect_client, unproxied,
};
use crate::config::{AppConfig, EgressMode};
use reqwest::Client;
use std::time::Duration;

const TOKEN_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone)]
pub struct OauthClients {
    direct: Client,
    proxied: Result<Client, ClientUnavailable>,
}

impl OauthClients {
    pub fn new(config: &AppConfig) -> Self {
        Self {
            direct: build(EgressMode::Direct, config).unwrap_or_else(|_| no_redirect_client()),
            proxied: build(EgressMode::Proxied, config),
        }
    }

    /// The client for a route with `egress`, or why none may be used.
    pub fn for_egress(&self, egress: EgressMode) -> Result<&Client, ClientUnavailable> {
        match egress {
            EgressMode::Direct => Ok(&self.direct),
            EgressMode::Proxied => self.proxied.as_ref().map_err(|e| *e),
        }
    }
}

/// One client for every route, for callers (and tests) that pin it.
impl From<Client> for OauthClients {
    fn from(client: Client) -> Self {
        Self {
            direct: client.clone(),
            proxied: Ok(client),
        }
    }
}

/// Token endpoints never redirect, and a followed 307/308 would resend the
/// refresh token or authorization code to wherever `Location` points.
/// `tls.upstream_ca_bundle` is trusted as on routes: it is where an
/// intercepting egress proxy's CA goes, and token calls now cross it too.
fn build(egress: EgressMode, config: &AppConfig) -> Result<Client, ClientUnavailable> {
    let proxy = egress_proxy(egress, config)?;
    let mut builder = unproxied()
        .timeout(TOKEN_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none());
    if let Some(p) = proxy.clone() {
        builder = builder.proxy(p);
    }
    if let Some(ca) = config
        .tls
        .as_ref()
        .and_then(|t| t.upstream_ca_bundle.as_ref())
    {
        builder = add_ca_bundle(builder, ca);
    }
    finish(builder, proxy.is_some(), no_redirect_client)
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::any;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn config(extra: &str) -> AppConfig {
        crate::config::parse_config_str(&format!(
            "listen:\n  host: \"127.0.0.1\"\n  port: 9200\ntools: []\n{extra}"
        ))
        .unwrap()
    }

    #[tokio::test]
    async fn a_proxied_token_call_goes_through_the_egress_proxy() {
        // An HTTP proxy receives absolute-form requests for http:// URLs,
        // so only the proxy can answer this unresolvable host.
        let proxy = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(200))
            .mount(&proxy)
            .await;
        let clients = OauthClients::new(&config(&format!("egress_proxy: \"{}\"", proxy.uri())));
        let resp = clients
            .for_egress(EgressMode::Proxied)
            .unwrap()
            .post("http://token.invalid/oauth/token")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        assert_eq!(proxy.received_requests().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn a_direct_token_call_skips_the_egress_proxy() {
        let proxy = MockServer::start().await;
        let token = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(200))
            .mount(&token)
            .await;
        let clients = OauthClients::new(&config(&format!("egress_proxy: \"{}\"", proxy.uri())));
        let url = format!("{}/oauth/token", token.uri());
        let resp = clients
            .for_egress(EgressMode::Direct)
            .unwrap()
            .post(url)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        assert!(proxy.received_requests().await.unwrap().is_empty());
    }

    #[test]
    fn a_proxied_token_call_fails_closed_without_enforcement() {
        let clients = OauthClients::new(&config(""));
        assert_eq!(
            clients.for_egress(EgressMode::Proxied).err(),
            Some(ClientUnavailable::ProxyUnconfigured)
        );
        assert!(clients.for_egress(EgressMode::Direct).is_ok());
    }

    #[test]
    fn external_mode_sends_proxied_token_calls_directly() {
        let clients = OauthClients::new(&config("egress:\n  mode: external"));
        assert!(clients.for_egress(EgressMode::Proxied).is_ok());
    }

    /// An HTTPS token endpoint signed by a private CA (127.0.0.1 SAN); the
    /// CA's PEM is returned for `tls.upstream_ca_bundle`.
    async fn private_ca_endpoint() -> (u16, String) {
        use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, SanType};
        crate::admin::https::install_crypto_provider_once();
        let ca_key = KeyPair::generate().unwrap();
        let mut ca = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca = ca.self_signed(&ca_key).unwrap();
        let leaf_key = KeyPair::generate().unwrap();
        let mut leaf = CertificateParams::new(Vec::<String>::new()).unwrap();
        leaf.subject_alt_names = vec![SanType::IpAddress("127.0.0.1".parse().unwrap())];
        let leaf = leaf.signed_by(&leaf_key, &ca, &ca_key).unwrap();
        let tls = axum_server::tls_rustls::RustlsConfig::from_pem(
            leaf.pem().into_bytes(),
            leaf_key.serialize_pem().into_bytes(),
        )
        .await
        .unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        // No routes (the QA contract counts routes in src/): any answer,
        // here a 404, proves the TLS handshake verified.
        let app = axum::Router::new();
        tokio::spawn(axum_server::from_tcp_rustls(listener, tls).serve(app.into_make_service()));
        (port, ca.pem())
    }

    #[tokio::test]
    async fn token_calls_trust_the_upstream_ca_bundle() {
        // AGENT-269 review: an intercepting egress proxy's CA goes in
        // tls.upstream_ca_bundle, and token calls now cross that proxy.
        let (port, ca_pem) = private_ca_endpoint().await;
        let dir = tempfile::TempDir::new().unwrap();
        let ca_path = dir.path().join("ca.pem");
        std::fs::write(&ca_path, ca_pem).unwrap();
        let url = format!("https://127.0.0.1:{port}/token");
        let with_ca = OauthClients::new(&config(&format!(
            "tls:\n  upstream_ca_bundle: \"{}\"",
            ca_path.display()
        )));
        let resp = with_ca
            .for_egress(EgressMode::Direct)
            .unwrap()
            .post(&url)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 404);
        let without = OauthClients::new(&config(""));
        assert!(
            without
                .for_egress(EgressMode::Direct)
                .unwrap()
                .post(&url)
                .send()
                .await
                .is_err(),
            "the private CA must not be trusted without the bundle"
        );
    }

    #[tokio::test]
    async fn token_calls_do_not_follow_redirects() {
        let token = MockServer::start().await;
        Mock::given(any())
            .respond_with(
                ResponseTemplate::new(307).insert_header("location", "http://elsewhere.invalid/"),
            )
            .mount(&token)
            .await;
        let clients = OauthClients::new(&config(""));
        let resp = clients
            .for_egress(EgressMode::Direct)
            .unwrap()
            .post(format!("{}/oauth/token", token.uri()))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 307);
    }
}
