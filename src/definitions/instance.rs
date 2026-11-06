use super::{Error, Instance, Pin};
use crate::registrations::{
    AuthSpec, Kind, McpConfig, Protocol, Registration, api::AdminRegistrationsState,
};
use axum::{
    Json,
    extract::{Path, Request, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};

pub(super) async fn create(
    State(state): State<AdminRegistrationsState>,
    Path(name): Path<String>,
    request: Request,
) -> Result<Response, Error> {
    crate::registrations::validate_name(&name).map_err(|_| Error::Invalid)?;
    let input: Instance = super::decode(&super::api::body(request).await?)?;
    let registration = prepare(&state, name, input).await?;
    if state.local_listener.as_ref().is_some_and(|(host, port)| {
        crate::registrations::protocol::is_self(&registration.upstream, host, *port)
    }) {
        return Err(Error::Invalid);
    }
    insert(&state, &registration).await?;
    // Disabled rows need no catalog activation, credential resolution or provider I/O.
    Ok((
        StatusCode::CREATED,
        Json(super::promotion::describe(&state, &registration.name).await?),
    )
        .into_response())
}
fn registration(
    name: String,
    input: Instance,
    pin: Pin,
    description: String,
) -> Result<Registration, Error> {
    let mut r = Registration::new(
        name,
        Kind::Tool,
        description,
        input.upstream,
        AuthSpec::None,
    );
    r.disabled = true;
    r.egress = crate::config::EgressMode::Direct;
    r.protocol = Protocol::McpStreamableHttp;
    r.mcp = Some(McpConfig {
        compact: false,
        protocol_version: crate::registrations::protocol::VERSION.into(),
        allow_private_destination: input.allow_private_destination,
        definition: Some(pin),
        definition_activation: None,
    });
    validate(&r)?;
    Ok(r)
}

async fn prepare(
    state: &AdminRegistrationsState,
    name: String,
    input: Instance,
) -> Result<Registration, Error> {
    let definition = state
        .repo
        .get_definition(&input.definition.id, input.definition.revision)
        .await?;
    if !definition
        .auth_profiles
        .iter()
        .any(|a| a.id == input.auth_profile_id)
    {
        return Err(Error::Invalid);
    }
    let pin = Pin {
        id: definition.id.clone(),
        revision: definition.revision,
        digest: definition.digest()?,
        auth_profile_id: input.auth_profile_id.clone(),
    };
    registration(name, input, pin, definition.summary)
}

async fn insert(state: &AdminRegistrationsState, registration: &Registration) -> Result<(), Error> {
    if state.repo.create(registration).await.is_err() {
        return Err(
            if state
                .repo
                .get(&registration.name)
                .await
                .map_err(|_| Error::Backend)?
                .is_some()
            {
                Error::Conflict
            } else {
                Error::Backend
            },
        );
    }
    Ok(())
}

fn validate(r: &Registration) -> Result<(), Error> {
    crate::registrations::protocol::validate(
        r.protocol,
        r.mcp.as_ref(),
        r.kind,
        r.egress,
        &r.upstream,
        Some(&r.metadata),
    )
    .map_err(|_| Error::Invalid)
}
