//! Reveal-never owner API. No raw client material appears in responses.
use super::*;
use crate::auth_v2::OperatorIdentity;
use axum::{
    Extension, Json,
    extract::{Path, State},
    response::{IntoResponse, Response},
};
use secrecy::{ExposeSecret, SecretString};
use serde_json::json;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    profile: String,
    client_generation: u64,
    secret: SecretString,
}

pub(super) async fn set(
    State(rt): State<Arc<Runtime>>,
    Extension(owner): Extension<OperatorIdentity>,
    Path(name): Path<String>,
    body: axum::body::Bytes,
) -> Response {
    let input = parse(&body)
        .and_then(|v| serde_json::from_value::<Input>(v).map_err(|_| Error("invalid_request")));
    let result = match input {
        Ok(v) => {
            rt.set_client(
                &owner.public_id,
                &name,
                &v.profile,
                v.client_generation,
                v.secret.expose_secret(),
            )
            .await
        }
        Err(e) => Err(e),
    };
    reply(result)
}

pub(super) async fn get(
    State(rt): State<Arc<Runtime>>,
    Extension(owner): Extension<OperatorIdentity>,
    Path((name, profile, generation)): Path<(String, String, u64)>,
) -> Response {
    reply(inspect(&rt, &owner.public_id, &name, &profile, generation, false).await)
}

pub(super) async fn delete(
    State(rt): State<Arc<Runtime>>,
    Extension(owner): Extension<OperatorIdentity>,
    Path((name, profile, generation)): Path<(String, String, u64)>,
) -> Response {
    reply(inspect(&rt, &owner.public_id, &name, &profile, generation, true).await)
}

async fn inspect(
    rt: &Runtime,
    owner: &str,
    name: &str,
    profile: &str,
    generation: u64,
    delete: bool,
) -> Result<Value> {
    if !identifier(name) || !identifier(profile) || generation == 0 || generation > i64::MAX as u64
    {
        return Err(Error("invalid_request"));
    }
    let mut tx = rt.pool.begin_with("BEGIN IMMEDIATE").await?;
    // Owner/profile metadata remains retireable after registration removal or key loss.
    if delete {
        sqlx::query("UPDATE oauth_consent_clients SET retired_at=? WHERE owner_id=? AND profile_id=? AND client_generation=? AND retired_at IS NULL")
            .bind(now()).bind(owner).bind(profile).bind(generation as i64).execute(&mut *tx).await?;
    }
    let row = sqlx::query("SELECT retired_at,EXISTS(SELECT 1 FROM credential_secrets s WHERE s.secret_ref=c.secret_ref AND s.tombstoned_at IS NULL) AS live FROM oauth_consent_clients c WHERE owner_id=? AND profile_id=? AND client_generation=?")
        .bind(owner).bind(profile).bind(generation as i64).fetch_optional(&mut *tx).await?;
    let state = match row {
        None => "absent",
        Some(r) if r.get::<Option<i64>, _>("retired_at").is_some() => "retired",
        Some(r) if r.get::<bool, _>("live") => "configured",
        _ => "unavailable",
    };
    tx.commit().await?;
    Ok(json!({"profile":profile,"client_generation":generation,"state":state}))
}

fn reply(result: Result<Value>) -> Response {
    match result {
        Ok(v) => Json(v).into_response(),
        Err(e) => super::api::error(e),
    }
}
