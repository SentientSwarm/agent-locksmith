use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::{Value, json};

#[derive(Clone, Copy, Debug)]
pub(super) struct Failure(pub u16, pub &'static str);
impl Failure {
    pub fn response(self) -> Response {
        let mut response = (
            StatusCode::from_u16(self.0).unwrap(),
            Json(json!({"error":{"code":self.1,"message":"Native MCP request refused"}})),
        )
            .into_response();
        if self.0 == 429 {
            response
                .headers_mut()
                .insert("retry-after", "1".parse().unwrap());
        }
        response
    }
}
pub(super) fn rpc(id: Option<&Value>, code: i64, reason: &'static str) -> Response {
    let id = id.filter(|value| super::wire::id(value));
    Json(json!({"jsonrpc":"2.0", "id":id, "error":{"code":code,
        "message":"Native MCP request refused", "data":{"code":reason}}}))
    .into_response()
}
