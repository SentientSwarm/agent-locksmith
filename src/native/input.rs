use super::{
    error::{Failure, rpc},
    wire,
};
use crate::auth_v2::AgentIdentity;
use axum::{
    body::{Body, to_bytes},
    extract::Request,
    http::Method,
    response::Response,
};
use serde_json::Value;
use tokio_util::sync::CancellationToken;

pub(super) struct Input {
    pub request: Request,
    pub value: Option<Value>,
}
impl Input {
    pub async fn read(req: Request, limit: usize) -> Result<Self, Box<Response>> {
        let (parts, body) = req.into_parts();
        let bytes = to_bytes(body, limit)
            .await
            .map_err(|_| Failure(413, "request_body_limit").response())?;
        let value = parse(&bytes, &parts.method)?;
        Ok(Self {
            request: Request::from_parts(parts, Body::from(bytes)),
            value,
        })
    }
}
fn parse(bytes: &[u8], method: &Method) -> Result<Option<Value>, Box<Response>> {
    if method != Method::POST {
        return if bytes.is_empty() {
            Ok(None)
        } else {
            Err(Box::new(Failure(400, "unexpected_body").response()))
        };
    }
    let value = super::json::parse(bytes).map_err(|_| rpc(None, -32700, "invalid_json"))?;
    if value["method"] == "initialize" && value["params"]["protocolVersion"] != wire::VERSION {
        return Err(Box::new(Failure(400, "protocol_version").response()));
    }
    wire::envelope(&value).map_err(|(code, reason)| rpc(value.get("id"), code, reason))?;
    Ok(Some(value))
}
pub(super) fn identity(req: &Request) -> Result<AgentIdentity, Failure> {
    req.extensions()
        .get::<AgentIdentity>()
        .cloned()
        .ok_or(Failure(401, "agent_identity_required"))
}
pub(super) fn cancellation(req: &Request) -> Result<CancellationToken, Failure> {
    req.extensions()
        .get::<CancellationToken>()
        .cloned()
        .ok_or(Failure(503, "native_boundary_missing"))
}
