use super::context::Context;
use rmcp::{ErrorData, RoleServer, ServerHandler, model::*, service::RequestContext};
use std::{borrow::Cow, sync::Arc};

#[derive(Clone)]
pub(super) struct Handler(
    pub Arc<Context>,
    pub Option<crate::repo::audit::AuditRepository>,
);
impl Handler {
    async fn check(&self) -> Result<(), ErrorData> {
        self.0
            .current()
            .await
            .map_err(|_| error("authority_changed"))
    }
}
pub(super) fn error(code: &'static str) -> ErrorData {
    ErrorData::new(
        ErrorCode(-32050),
        "Native MCP request refused",
        Some(serde_json::json!({"code":code})),
    )
}
impl ServerHandler for Handler {
    fn supported_protocol_versions(&self) -> Cow<'static, [ProtocolVersion]> {
        Cow::Owned(vec![ProtocolVersion::V_2025_11_25])
    }
    fn get_info(&self) -> InitializeResult {
        InitializeResult::new(ServerCapabilities::builder().enable_tools().build())
            .with_protocol_version(ProtocolVersion::V_2025_11_25)
            .with_server_info(Implementation::new("locksmith", env!("CARGO_PKG_VERSION")))
    }
    async fn initialize(
        &self,
        request: InitializeRequestParams,
        ctx: RequestContext<RoleServer>,
    ) -> Result<InitializeResult, ErrorData> {
        self.check().await?;
        super::audit::record(&self.1, &self.0, "initialize", true).await;
        ctx.peer.set_peer_info(request);
        Ok(self.get_info())
    }
    async fn ping(&self, _ctx: RequestContext<RoleServer>) -> Result<(), ErrorData> {
        self.check().await?;
        super::audit::record(&self.1, &self.0, "ping", true).await;
        Ok(())
    }
    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _ctx: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        self.check().await?;
        super::audit::record(&self.1, &self.0, "tools/list", true).await;
        Ok(ListToolsResult::default())
    }
    async fn call_tool(
        &self,
        _request: CallToolRequestParams,
        _ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        self.check().await?;
        super::audit::record(&self.1, &self.0, "tools/call", false).await;
        Err(error("tool_not_approved"))
    }
}
