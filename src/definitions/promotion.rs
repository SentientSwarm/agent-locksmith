//! Dedicated definition transition. No account, grant or upstream operation.
use super::{Activation, Error, Mechanism, eligibility};
use crate::registrations::{AuthSpec, Registration, api::AdminRegistrationsState};
use axum::{
    Json,
    extract::{Path, Request, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::{Row, SqliteConnection};
use std::time::Duration;

struct Input {
    enabled: bool,
    compact: bool,
    profile: Option<String>,
}
fn input(bytes: &[u8]) -> Result<Input, Error> {
    let v: Value = super::decode(bytes)?;
    let o = v.as_object().ok_or(Error::Invalid)?;
    let enabled = o
        .get("enabled")
        .and_then(Value::as_bool)
        .ok_or(Error::Invalid)?;
    if !enabled {
        if o.len() != 1 {
            return Err(Error::Invalid);
        }
        return Ok(Input {
            enabled,
            compact: false,
            profile: None,
        });
    }
    if o.keys()
        .any(|k| !["enabled", "compact", "oauth_profile_id"].contains(&k.as_str()))
    {
        return Err(Error::Invalid);
    }
    let compact = o
        .get("compact")
        .and_then(Value::as_bool)
        .ok_or(Error::Invalid)?;
    let profile = o
        .get("oauth_profile_id")
        .map(|v| v.as_str().map(str::to_owned).ok_or(Error::Invalid))
        .transpose()?;
    Ok(Input {
        enabled,
        compact,
        profile,
    })
}
pub(super) async fn activate(
    State(state): State<AdminRegistrationsState>,
    Path(name): Path<String>,
    request: Request,
) -> Response {
    let expected = request
        .headers()
        .get_all("if-match")
        .iter()
        .collect::<Vec<_>>();
    if expected.is_empty() {
        return Error::Precondition.into_response();
    }
    if expected.len() != 1 {
        return Error::Invalid.into_response();
    }
    let Ok(expected) = expected[0].to_str().map(str::to_owned) else {
        return Error::Invalid.into_response();
    };
    if expected.len() != 64 || !expected.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Error::Invalid.into_response();
    }
    let body = match super::api::body(request).await.and_then(|b| input(&b)) {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };
    match tokio::time::timeout(Duration::from_secs(10), change(&state, &name, &expected, body)).await {
        Ok(Ok(v)) => Json(v).into_response(),
        Ok(Err(e)) => e.into_response(),
        Err(_) => (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"saved":null,"activation":"pending","outcome":"unknown","error":{"code":"definition_unavailable","message":"operation timed out; submitted persistence may have completed. Read fresh state before repair."}}))).into_response(),
    }
}
fn revision(instance: &str, revision: i64) -> String {
    let mut h = Sha256::new();
    h.update(b"locksmith-definition-control-v1\0");
    h.update(instance.as_bytes());
    h.update(revision.to_be_bytes());
    format!("{:x}", h.finalize())
}
async fn read(c: &mut SqliteConnection, name: &str) -> Result<(Registration, String), Error> {
    let row = sqlx::query("SELECT r.*,i.instance_id,i.revision FROM registrations r JOIN registration_instances i USING(name) WHERE r.name=?").bind(name).fetch_optional(c).await?.ok_or(Error::NotFound)?;
    let rev = revision(row.get("instance_id"), row.get("revision"));
    let r = crate::registrations::repo::row_to_registration(row).map_err(|_| Error::Unavailable)?;
    if !r.definition_pinned() {
        return Err(Error::NotFound);
    }
    Ok((r, rev))
}
pub(crate) async fn describe(state: &AdminRegistrationsState, name: &str) -> Result<Value, Error> {
    let mut c = state.repo.pool.acquire().await?;
    let (r, revision) = read(&mut c, name).await?;
    Ok(document(state, &r, revision))
}
fn document(state: &AdminRegistrationsState, r: &Registration, revision: String) -> Value {
    let mut value = state.describe(r);
    let activation = r
        .mcp
        .as_ref()
        .and_then(|m| m.definition_activation.as_ref());
    let (kind, profile, matched) = match activation {
        None => (Value::Null, Value::Null, "not_applicable"),
        Some(Activation::None) => (json!("none"), Value::Null, "not_applicable"),
        Some(Activation::StoredBearer) => (json!("stored_bearer"), Value::Null, "not_applicable"),
        Some(Activation::ControlledOauth {
            profile_id,
            profile_digest,
        }) => {
            let matched = match state
                .consent
                .as_ref()
                .and_then(|rt| rt.profile(profile_id).ok())
            {
                None => "unavailable",
                Some(p) if p.digest().ok().as_ref() == Some(profile_digest) => "matches",
                Some(_) => "changed",
            };
            (json!("controlled_oauth"), json!(profile_id), matched)
        }
    };
    value["definition_control"] = json!({"revision":revision,"phase":if activation.is_some() {"promoted"} else {"disabled"},"selection_kind":kind,"oauth_profile_id":profile,"profile_match":matched});
    value
}
async fn change(
    state: &AdminRegistrationsState,
    name: &str,
    expected: &str,
    input: Input,
) -> Result<Value, Error> {
    let mut tx = state.repo.pool.begin_with("BEGIN IMMEDIATE").await?;
    let (mut r, current) = read(&mut tx, name).await?;
    if current != expected {
        return Err(Error::Conflict);
    }
    let before = r.clone();
    let mcp = r.mcp.as_mut().ok_or(Error::Invalid)?;
    if input.enabled {
        let declared =
            eligibility::declared(&mut tx, mcp.definition.as_ref().ok_or(Error::Invalid)?).await?;
        let (activation, auth) = match declared.mechanism {
            Mechanism::None if input.profile.is_none() => (Activation::None, AuthSpec::None),
            Mechanism::Bearer if input.profile.is_none() => {
                (Activation::StoredBearer, AuthSpec::None)
            }
            Mechanism::OauthProvider => {
                let id = input.profile.as_deref().ok_or(Error::Invalid)?;
                let p = state
                    .consent
                    .as_ref()
                    .ok_or(Error::Unavailable)?
                    .profile(id)
                    .map_err(|_| Error::Invalid)?;
                if p.hosted() || p.resource != r.upstream {
                    return Err(Error::Invalid);
                }
                (
                    Activation::ControlledOauth {
                        profile_id: p.id.clone(),
                        profile_digest: p.digest().map_err(|_| Error::Invalid)?,
                    },
                    p.auth_spec(),
                )
            }
            _ => return Err(Error::Invalid),
        };
        if !eligibility::mechanism(&declared, &activation) {
            return Err(Error::Invalid);
        }
        if mcp
            .definition_activation
            .as_ref()
            .is_some_and(|a| a != &activation || mcp.compact != input.compact)
        {
            return Err(Error::Conflict);
        }
        mcp.definition_activation = Some(activation);
        mcp.compact = input.compact;
        r.auth = auth;
        r.disabled = false;
        if state.local_listener.as_ref().is_some_and(|(host, port)| {
            crate::registrations::protocol::is_self(&r.upstream, host, *port)
        }) {
            return Err(Error::Invalid);
        }
        eligibility::selected(&mut tx, &r, None).await?;
    } else {
        // Local revocation must work even when the loaded profile/key is absent.
        mcp.definition_activation = None;
        r.auth = AuthSpec::None;
        r.disabled = true;
    }
    if r != before {
        sqlx::query("UPDATE registrations SET auth_json=?,mcp_json=?,disabled=?,updated_at=unixepoch() WHERE name=?")
            .bind(serde_json::to_string(&r.auth).map_err(|_| Error::Invalid)?)
            .bind(serde_json::to_string(&r.mcp).map_err(|_| Error::Invalid)?)
            .bind(r.disabled).bind(name).execute(&mut *tx).await?;
    }
    tx.commit().await?;
    if state.refresh_native_catalog().await.is_err() {
        return Err(Error::SavedUnavailable);
    }
    describe(state, name).await
}
