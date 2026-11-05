#![allow(dead_code)] // Shared support: each integration target uses a different subset.
use agent_locksmith::{
    config::parse_config_str,
    registrations::{
        AuthSpec, Catalog, Kind, McpConfig, Protocol, Registration, RegistrationRepository,
    },
    repo::{AgentCredentialRepository, AgentRepository},
};
use arc_swap::ArcSwap;
use axum::{
    Router,
    body::{Body, to_bytes},
    http::Request,
    response::Response,
};
use serde_json::{Value, json};
use std::sync::Arc;
use tower::ServiceExt;

#[path = "setup.rs"]
mod setup;
pub struct Fixture {
    pub _dir: tempfile::TempDir,
    pub pool: sqlx::SqlitePool,
    pub repo: Arc<RegistrationRepository>,
    pub agents: AgentRepository,
    pub bindings: AgentCredentialRepository,
    pub agent_id: i64,
    pub bearer: String,
    pub catalog: Arc<ArcSwap<Catalog>>,
    pub runtime: Arc<agent_locksmith::native::Runtime>,
    pub app: Router,
}
impl Fixture {
    pub async fn new(config: &str) -> Self {
        let (dir, pool, repo) = setup::store().await;
        let (agents, bindings, agent_id, bearer) = setup::caller(&pool).await;
        let cfg = parse_config_str(&format!("listen:\n  port: 9200\n{config}")).unwrap();
        let catalog = setup::catalog(&repo).await;
        let runtime = agent_locksmith::native::Runtime::new(
            cfg.mcp.clone(),
            Some(repo.clone()),
            catalog.clone(),
        );
        let app = setup::router(cfg, &repo, &agents, &bindings, &catalog, &runtime);
        Self {
            _dir: dir,
            pool,
            repo,
            agents,
            bindings,
            agent_id,
            bearer,
            catalog,
            runtime,
            app,
        }
    }
    pub async fn request(
        &self,
        path: &str,
        method: &str,
        body: Value,
        session: Option<&str>,
    ) -> Response {
        let mut req = Request::builder()
            .method(method)
            .uri(path)
            .header("host", "localhost")
            .header("authorization", &self.bearer)
            .header("accept", "application/json, text/event-stream")
            .header("content-type", "application/json");
        if let Some(session) = session {
            req = req
                .header("mcp-session-id", session)
                .header("mcp-protocol-version", "2025-11-25");
        }
        let body = if body.is_null() {
            Body::empty()
        } else {
            Body::from(body.to_string())
        };
        self.app
            .clone()
            .oneshot(req.body(body).unwrap())
            .await
            .unwrap()
    }
    pub async fn open(&self) -> String {
        let response = self.request("/mcp/native", "POST", init(0), None).await;
        assert_eq!(response.status(), 200);
        let session = response.headers()["mcp-session-id"]
            .to_str()
            .unwrap()
            .to_owned();
        assert_eq!(
            rpc(response).await["result"]["protocolVersion"],
            "2025-11-25"
        );
        let response = self
            .request(
                "/mcp/native",
                "POST",
                json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
                Some(&session),
            )
            .await;
        assert_eq!(response.status(), 202);
        session
    }
    pub async fn call(&self, session: &str, id: i64, method: &str) -> Response {
        self.request(
            "/mcp/native",
            "POST",
            json!({"jsonrpc":"2.0","id":id,"method":method}),
            Some(session),
        )
        .await
    }
    pub async fn refresh(&self) {
        self.catalog
            .store(Arc::new(Catalog::from_repo(&self.repo).await.unwrap()));
    }
}
pub fn native(name: &str) -> Registration {
    let mut r = Registration::new(
        name.into(),
        Kind::Tool,
        String::new(),
        "https://example.com/mcp".into(),
        AuthSpec::None,
    );
    r.protocol = Protocol::McpStreamableHttp;
    r.mcp = Some(McpConfig {
        protocol_version: "2025-11-25".into(),
        allow_private_destination: false,
        definition: None,
    });
    r
}
pub fn init(id: i64) -> Value {
    json!({"jsonrpc":"2.0","id":id,"method":"initialize","params":{
    "protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"fixture","version":"1"}}})
}
pub async fn rpc(response: Response) -> Value {
    let bytes = to_bytes(response.into_body(), 262144).await.unwrap();
    let text = std::str::from_utf8(&bytes).unwrap();
    let raw = text
        .lines()
        .find_map(|line| line.strip_prefix("data: "))
        .unwrap_or(text);
    serde_json::from_str(raw).unwrap()
}
pub async fn released(f: &Fixture) {
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while f.runtime.snapshot().entries > 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}
