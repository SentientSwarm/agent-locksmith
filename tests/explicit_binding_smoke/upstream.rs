use super::fixture::Fixture;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate, matchers::any};

pub const X: &str = "synthetic-private-account-x";
pub const Y: &str = "synthetic-private-account-y";
#[derive(Clone)]
struct Accounts(Arc<[AtomicUsize; 3]>);
impl Respond for Accounts {
    fn respond(&self, req: &Request) -> ResponseTemplate {
        let auth = req
            .headers
            .get("authorization")
            .map(|h| h.to_str().unwrap());
        let account = match auth {
            Some(v) if v == format!("Bearer {X}") => 0,
            Some(v) if v == format!("Bearer {Y}") => 1,
            None if req.url.path() == "/noauth" => 2,
            _ => return ResponseTemplate::new(401),
        };
        assert!(
            !req.headers.contains_key("x-api-key"),
            "caller API key was not stripped"
        );
        self.0[account].fetch_add(1, Ordering::SeqCst);
        ResponseTemplate::new(200).set_body_string(["X", "Y", "NONE"][account])
    }
}
pub struct Receiver {
    pub server: MockServer,
    counts: Accounts,
}
impl Receiver {
    pub async fn start() -> Self {
        let server = MockServer::builder().start().await;
        let counts = Accounts(Arc::new(std::array::from_fn(|_| AtomicUsize::new(0))));
        Mock::given(any())
            .respond_with(counts.clone())
            .mount(&server)
            .await;
        Self { server, counts }
    }
    pub async fn snapshot(&self) -> ([usize; 3], usize) {
        (
            std::array::from_fn(|i| self.counts.0[i].load(Ordering::SeqCst)),
            self.server.received_requests().await.unwrap().len(),
        )
    }
}
pub async fn call(f: &Fixture, token: Option<&str>, route: &str) -> reqwest::Response {
    let mut request = f
        .http
        .get(f.url(&format!("/api/{route}")))
        .header("x-api-key", "synthetic-caller-key");
    if let Some(token) = token {
        request = request.bearer_auth(token);
    }
    request.send().await.unwrap()
}
pub async fn allowed(f: &Fixture, r: &Receiver, token: &str, route: &str, account: &str) {
    let before = r.snapshot().await;
    let response = call(f, Some(token), route).await;
    assert_eq!(response.status(), 200, "allowed {route}");
    assert_eq!(response.text().await.unwrap(), account);
    let mut expected = before.0;
    expected[["X", "Y", "NONE"]
        .iter()
        .position(|a| *a == account)
        .unwrap()] += 1;
    assert_eq!(r.snapshot().await, (expected, before.1 + 1));
}
pub async fn denied(
    f: &Fixture,
    r: &Receiver,
    token: Option<&str>,
    route: &str,
    status: u16,
    code: &str,
) {
    let before = r.snapshot().await;
    let response = call(f, token, route).await;
    assert_eq!(response.status(), status, "denied {route}");
    let body = response.text().await.unwrap();
    assert!(body.contains(code), "expected safe error class {code}");
    super::safety::no_values(&body, &[]);
    assert_eq!(
        r.snapshot().await,
        before,
        "denial reached receiving upstream"
    );
    println!("denial {route}: {status}/{code}, received_delta=0 operations_delta=0");
}

pub async fn closed(address: std::net::SocketAddr) {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    while std::net::TcpStream::connect_timeout(&address, std::time::Duration::from_millis(100))
        .is_ok()
    {
        assert!(
            tokio::time::Instant::now() < deadline,
            "fixture listener did not close"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
}
