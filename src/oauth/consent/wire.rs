use super::{Error, Result, Runtime, config, token};
use futures_util::StreamExt;
use locksmith_mcp_transport::{Client, Limits};
use rmcp::{
    model::{ClientJsonRpcMessage, ServerJsonRpcMessage},
    transport::streamable_http_client::{
        StreamableHttpClient, StreamableHttpPostResponse as Reply,
    },
};
use serde_json::{Value, json};
use sqlx::{Row, sqlite::SqliteRow};
use std::{collections::HashMap, sync::Arc};

enum Guard<'a> {
    Consent(&'a SqliteRow),
    Refresh(&'a super::refresh::Claim),
}

pub(crate) struct Wire<'a> {
    pub(super) stage: std::sync::Arc<std::sync::Mutex<&'static str>>,
    runtime: &'a Runtime,
    guard: Guard<'a>,
    profile: &'a config::Profile,
    token: &'a str,
    client: Client,
    session: Option<Arc<str>>,
    sequence: u64,
}

impl<'a> Wire<'a> {
    pub fn new(
        runtime: &'a Runtime,
        attempt: &'a SqliteRow,
        token: &'a str,
        stage: std::sync::Arc<std::sync::Mutex<&'static str>>,
    ) -> Result<Self> {
        let profile = runtime.profile(attempt.get("profile_id"))?;
        Ok(Self {
            runtime,
            guard: Guard::Consent(attempt),
            profile,
            token,
            stage,
            client: client(profile)?,
            session: None,
            sequence: 0,
        })
    }
    pub(super) fn refresh(
        runtime: &'a Runtime,
        claim: &'a super::refresh::Claim,
        token: &'a str,
        stage: std::sync::Arc<std::sync::Mutex<&'static str>>,
    ) -> Result<Self> {
        let profile = runtime.profile(&claim.profile_id)?;
        Ok(Self {
            runtime,
            guard: Guard::Refresh(claim),
            profile,
            token,
            stage,
            client: claim.wire_client.clone(),
            session: None,
            sequence: 0,
        })
    }
    pub fn enter(&self, stage: &'static str) {
        *self.stage.lock().expect("stage") = stage;
    }

    pub async fn initialize(&mut self) -> Result<Value> {
        self.enter("initialize");
        let result = self
            .rpc(
                "initialize",
                json!({"protocolVersion":"2025-11-25",
            "capabilities":{}, "clientInfo":{"name":"locksmith-controlled-consent","version":"0.0.0"}}),
            )
            .await?;
        if result["protocolVersion"] != "2025-11-25"
            || !result["capabilities"].is_object()
            || !result["serverInfo"].is_object()
        {
            return Err(Error("initialize_refused"));
        }
        self.enter("initialized");
        let message = json!({"jsonrpc":"2.0","method":"notifications/initialized"});
        if !matches!(self.post(message).await?, Reply::Accepted) {
            return Err(Error("unexpected_initialized_response"));
        }
        Ok(result)
    }

    pub async fn rpc(&mut self, method: &str, params: Value) -> Result<Value> {
        self.sequence += 1;
        let id = self.sequence;
        let reply = self
            .post(json!({"jsonrpc":"2.0","id":id,"method":method,"params":params}))
            .await?;
        let (message, session) = decode(reply).await?;
        if let Some(session) = session {
            if self
                .session
                .as_ref()
                .is_some_and(|old| old.as_ref() != session)
            {
                return Err(Error("session_changed"));
            }
            self.session = Some(session.into());
        }
        let value = serde_json::to_value(message).map_err(|_| Error("mcp_response_invalid"))?;
        if value["jsonrpc"] != "2.0" {
            return Err(Error("mcp_protocol_mismatch"));
        }
        if value["id"] != id {
            return Err(Error("response_id_mismatch"));
        }
        if value.get("error").is_some() {
            return Err(Error("rpc_error"));
        }
        if !value["result"].is_object() {
            return Err(Error("mcp_result_not_object"));
        }
        Ok(value["result"].clone())
    }

    async fn post(&self, value: Value) -> Result<Reply> {
        match self.guard {
            Guard::Consent(a) => self.runtime.check(a).await?,
            Guard::Refresh(c) => self.runtime.check_refresh(c).await?,
        }
        let message: ClientJsonRpcMessage =
            serde_json::from_value(value).map_err(|_| Error("mcp_request_invalid"))?;
        self.client
            .post_message(
                self.profile.resource.clone().into(),
                message,
                self.session.clone(),
                Some(self.token.into()),
                headers(),
            )
            .await
            .map_err(|_| Error("request_failed"))
    }

    pub async fn close(&self) -> &'static str {
        let Some(session) = self.session.clone() else {
            return "not_required";
        };
        // A 405 is accepted by this hook: true does not prove remote deletion.
        let accepted = self
            .client
            .delete_session(
                self.profile.resource.clone().into(),
                session,
                Some(self.token.into()),
                headers(),
            )
            .await
            .is_ok();
        if accepted {
            "attempted_helper_accepted"
        } else {
            "attempt_failed"
        }
    }
}

pub(super) fn client(profile: &config::Profile) -> Result<Client> {
    Client::new(
        Limits {
            timeout_ms: 5000,
            connect_timeout_ms: 3000,
            response_bytes: 524288,
            event_bytes: 524288,
            chunk_bytes: 524288,
            json_units: 32768,
            ..Default::default()
        },
        locksmith_mcp_transport::Certificate::from_pem_bundle(&token::roots(profile)?)
            .map_err(|_| Error("tls_unavailable"))?,
    )
    .map_err(|_| Error("tls_unavailable"))
}

fn headers() -> HashMap<axum::http::HeaderName, axum::http::HeaderValue> {
    HashMap::from([(
        axum::http::HeaderName::from_static("mcp-protocol-version"),
        axum::http::HeaderValue::from_static("2025-11-25"),
    )])
}

async fn decode(reply: Reply) -> Result<(ServerJsonRpcMessage, Option<String>)> {
    match reply {
        Reply::Json(value, session) => Ok((value, session)),
        Reply::Sse(mut stream, session) => {
            for _ in 0..128 {
                let event = stream
                    .next()
                    .await
                    .ok_or(Error("mcp_stream_ended"))?
                    .map_err(|_| Error("mcp_stream_refused"))?;
                let text = event.data.unwrap_or_default();
                if text.trim().is_empty() {
                    continue;
                }
                let value = event_message(&text)?;
                match value {
                    ServerJsonRpcMessage::Response(_) | ServerJsonRpcMessage::Error(_) => {
                        return Ok((value, session));
                    }
                    ServerJsonRpcMessage::Notification(_) => {}
                    _ => return Err(Error("server_request_unsupported")),
                }
            }
            Err(Error("mcp_event_limit"))
        }
        _ => Err(Error("mcp_response_missing")),
    }
}

fn event_message(text: &str) -> Result<ServerJsonRpcMessage> {
    let json = super::parse(text.as_bytes()).map_err(|_| Error("mcp_event_invalid"))?;
    serde_json::from_value(json).map_err(|_| Error("mcp_event_invalid"))
}
