use super::{
    handler::{Handler, error},
    ingress::Deadline,
};
use crate::native_authority::{self as authority, control::Control, dispatch::Invocation};
use rmcp::{ErrorData, RoleServer, model::*, service::RequestContext};
use serde_json::Value;

fn control(h: &Handler, ctx: &RequestContext<RoleServer>) -> Result<Control, ErrorData> {
    let deadline = ctx
        .extensions
        .get::<axum::http::request::Parts>()
        .and_then(|p| p.extensions.get::<Deadline>())
        .ok_or(error("request_deadline"))?;
    Ok(Control {
        request: ctx.ct.clone(),
        session: h.0.cancelled.clone(),
        deadline: deadline
            .0
            .min(tokio::time::Instant::now() + std::time::Duration::from_secs(10)),
    })
}
pub(super) async fn list(
    h: &Handler,
    ctx: RequestContext<RoleServer>,
) -> Result<ListToolsResult, ErrorData> {
    let control = control(h, &ctx)?;
    let runtime = h.0.runtime.upgrade().ok_or(error("shutting_down"))?;
    let Some(authority) = &runtime.authority else {
        h.0.current()
            .await
            .map_err(|_| error("authority_changed"))?;
        return Ok(ListToolsResult::default());
    };
    let tools = authority
        .scoped(control.run(list_current(h, authority, &control)))
        .await
        .map_err(|e| error(e.0))?;
    let tools = tools
        .into_iter()
        .map(serde_json::from_value)
        .collect::<Result<Vec<Tool>, _>>()
        .map_err(|_| error("review_invalid"))?;
    Ok(ListToolsResult::with_all_items(tools))
}
pub(super) async fn call(
    h: &Handler,
    request: CallToolRequestParams,
    ctx: RequestContext<RoleServer>,
) -> Result<CallToolResponse, ErrorData> {
    let control = control(h, &ctx)?;
    let runtime = h.0.runtime.upgrade().ok_or(error("shutting_down"))?;
    let authority = runtime
        .authority
        .as_ref()
        .ok_or(error("tool_not_approved"))?;
    let audit = h.1.as_ref().ok_or(error("admission_audit_unavailable"))?;
    let invocation = match invocation(h, request) {
        Ok(call) => call,
        Err(e) => {
            denied(h, authority, &control, audit, &e).await?;
            return Err(e);
        }
    };
    let result = authority
        .dispatch(invocation, control, audit)
        .await
        .map_err(|e| error(e.0))?;
    let result: CallToolResult =
        serde_json::from_value(result).map_err(|_| error("tool_outcome_unknown"))?;
    Ok(result.into())
}

async fn list_current(
    h: &Handler,
    authority: &authority::runtime::Runtime,
    control: &Control,
) -> authority::Result<Vec<Value>> {
    h.0.current()
        .await
        .map_err(|_| authority::Error("authority_changed"))?;
    let mut tx = authority.repo.pool.begin().await?;
    let current = authority
        .effective(&mut tx, &h.0.identity.public_id, &h.0.name)
        .await?;
    tx.commit().await?;
    control.check()?;
    h.0.list(&current)
}

fn invocation(h: &Handler, request: CallToolRequestParams) -> Result<Invocation, ErrorData> {
    let (source, digest) =
        h.0.pins
            .lock()
            .unwrap()
            .selected(&request.name)
            .map_err(|e| error(e.0))?;
    Ok(Invocation {
        agent: h.0.identity.public_id.clone(),
        connection: h.0.name.clone(),
        name: request.name.to_string(),
        source,
        digest,
        arguments: Value::Object(request.arguments.unwrap_or_default()),
    })
}

async fn denied(
    h: &Handler,
    authority: &authority::runtime::Runtime,
    control: &Control,
    audit: &crate::repo::AuditRepository,
    e: &ErrorData,
) -> Result<(), ErrorData> {
    let code = e
        .data
        .as_ref()
        .and_then(|d| d["code"].as_str())
        .unwrap_or("");
    let reason = if code == "tools_list_required" {
        "tools_list_required"
    } else {
        "tool_not_approved"
    };
    let mut trace = authority::diagnostics::Trace::new(&h.0.identity.public_id, &h.0.name)
        .map_err(|e| error(e.0))?;
    let _ = authority
        .scoped(async {
            trace
                .finish(audit, control, &Err(authority::Error(reason)))
                .await;
            Ok(())
        })
        .await;
    Ok(())
}
