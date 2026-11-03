#![allow(dead_code)]
use locksmith_mcp_transport::sessions::{Config, Pool, Scope, Scoped};
use rmcp::{
    model::*,
    transport::streamable_http_server::session::{SessionId, SessionManager},
};
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio_util::sync::CancellationToken;

pub fn config() -> Config {
    Config {
        total: 3,
        per_owner: 2,
        per_connection: 1,
        handshake: Duration::from_millis(300),
        cleanup_grace: Duration::from_millis(25),
        ..Default::default()
    }
}
pub fn scoped(pool: &Pool<()>, owner: &str, connection: &str, authority: &str) -> Scoped<()> {
    pool.scoped(
        Scope {
            owner: owner.into(),
            connection: connection.into(),
            authority: authority.into(),
        },
        (),
        CancellationToken::new(),
    )
    .unwrap()
}
pub fn message(value: serde_json::Value) -> ClientJsonRpcMessage {
    serde_json::from_value(value).unwrap()
}
pub fn init() -> ClientJsonRpcMessage {
    message(
        serde_json::json!({"jsonrpc":"2.0","id":0,"method":"initialize","params":{
        "protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}),
    )
}
pub fn ping(id: i64) -> ClientJsonRpcMessage {
    message(serde_json::json!({"jsonrpc":"2.0","id":id,"method":"ping"}))
}
pub async fn until(mut predicate: impl FnMut() -> bool) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while !predicate() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("finite cleanup");
}
pub async fn open(manager: &Scoped<()>, handler: Handler) -> SessionId {
    let (id, transport) = manager.create_session().await.unwrap();
    start(manager, id.clone(), transport, handler);
    manager.initialize_session(&id, init()).await.unwrap();
    manager
        .accept_message(
            &id,
            message(serde_json::json!({"jsonrpc":"2.0","method":"notifications/initialized"})),
        )
        .await
        .unwrap();
    id
}
pub fn start(
    manager: &Scoped<()>,
    id: SessionId,
    transport: locksmith_mcp_transport::sessions::OwnedTransport<()>,
    handler: Handler,
) {
    let ct = manager.session_cancellation_token(&id);
    let owner = manager.clone();
    manager.spawn_session(id.clone(), async move {
        if let Ok(service) = rmcp::service::serve_server_with_ct(handler, transport, ct).await {
            owner.session_initialized(&id);
            let _ = service.waiting().await;
        }
        owner.close_session(&id).await.unwrap();
        true
    });
}
#[derive(Clone, Default)]
pub struct Handler {
    pub stall_init: bool,
    pub entered: Arc<AtomicUsize>,
    pub live: Arc<AtomicUsize>,
}
struct Live(Arc<AtomicUsize>);
impl Drop for Live {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}
impl Handler {
    async fn stall(&self) {
        self.live.fetch_add(1, Ordering::SeqCst);
        let _live = Live(self.live.clone());
        self.entered.fetch_add(1, Ordering::SeqCst);
        std::future::pending::<()>().await;
    }
}
impl rmcp::ServerHandler for Handler {
    async fn initialize(
        &self,
        _request: InitializeRequestParams,
        _ctx: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> Result<InitializeResult, rmcp::ErrorData> {
        if self.stall_init {
            self.stall().await;
        }
        Ok(InitializeResult::new(ServerCapabilities::default())
            .with_protocol_version(ProtocolVersion::V_2025_11_25))
    }
    async fn call_tool(
        &self,
        _request: CallToolRequestParams,
        _ctx: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> Result<CallToolResponse, rmcp::ErrorData> {
        self.stall().await;
        unreachable!()
    }
    async fn on_progress(
        &self,
        _notification: ProgressNotificationParam,
        _ctx: rmcp::service::NotificationContext<rmcp::RoleServer>,
    ) {
        self.stall().await;
    }
}
