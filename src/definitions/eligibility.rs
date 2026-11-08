//! One transaction-local pin/mechanism predicate for selection and consumption.
use super::{Activation, AuthProfile, Error, Mechanism, Pin};
use crate::registrations::{AuthSpec, Registration};
use sqlx::{Row, SqliteConnection};

pub(crate) async fn declared(c: &mut SqliteConnection, pin: &Pin) -> Result<AuthProfile, Error> {
    if !pin.id.starts_with("local.") {
        return Err(Error::Invalid);
    }
    let row = sqlx::query(
        "SELECT canonical_json,digest FROM integration_definitions WHERE id=? AND revision=?",
    )
    .bind(&pin.id)
    .bind(pin.revision)
    .fetch_optional(c)
    .await?
    .ok_or(Error::Invalid)?;
    let d = super::parse(row.get::<&str, _>("canonical_json").as_bytes())?;
    if d.id != pin.id
        || d.revision != pin.revision
        || d.digest()? != pin.digest
        || row.get::<&str, _>("digest") != pin.digest
    {
        return Err(Error::Invalid);
    }
    d.auth_profiles
        .into_iter()
        .find(|p| p.id == pin.auth_profile_id)
        .ok_or(Error::Invalid)
}

pub(crate) fn mechanism(p: &AuthProfile, activation: &Activation) -> bool {
    match (&p.mechanism, activation) {
        (Mechanism::None, Activation::None) | (Mechanism::Bearer, Activation::StoredBearer) => {
            p.required_scopes.is_empty()
        }
        (Mechanism::OauthProvider, Activation::ControlledOauth { .. }) => {
            !p.required_scopes.is_empty()
        }
        _ => false,
    }
}

pub(crate) async fn selected(
    c: &mut SqliteConnection,
    r: &Registration,
    auth: Option<&AuthSpec>,
) -> Result<(), Error> {
    let Some(mcp) = &r.mcp else {
        return Ok(());
    };
    let Some(pin) = &mcp.definition else {
        return if mcp.definition_activation.is_none() {
            Ok(())
        } else {
            Err(Error::Invalid)
        };
    };
    let activation = mcp.definition_activation.as_ref().ok_or(Error::Invalid)?;
    let declared = declared(c, pin).await?;
    if r.disabled || r.seed || !mechanism(&declared, activation) {
        return Err(Error::Invalid);
    }
    crate::registrations::protocol::validate(
        r.protocol,
        Some(mcp),
        r.kind,
        r.egress,
        &r.upstream,
        Some(&r.metadata),
    )
    .map_err(|_| Error::Invalid)?;
    match activation {
        Activation::None | Activation::StoredBearer if r.auth != AuthSpec::None => {
            return Err(Error::Invalid);
        }
        Activation::ControlledOauth { .. } if !matches!(r.auth, AuthSpec::OauthPkce { .. }) => {
            return Err(Error::Invalid);
        }
        _ => (),
    }
    if let AuthSpec::OauthPkce { scopes, .. } = &r.auth
        && scopes != &declared.required_scopes
    {
        return Err(Error::Invalid);
    }
    let Some(auth) = auth else {
        return Ok(());
    };
    match (activation, auth) {
        (Activation::None, AuthSpec::None) => Ok(()),
        (Activation::StoredBearer, AuthSpec::StoredBearer { secret_ref }) => {
            let live: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM credential_secrets WHERE secret_ref=? AND tombstoned_at IS NULL)").bind(secret_ref).fetch_one(c).await?;
            if live { Ok(()) } else { Err(Error::Invalid) }
        }
        (
            Activation::ControlledOauth {
                profile_id,
                profile_digest,
            },
            AuthSpec::ControlledOauth {
                profile_id: id,
                profile_digest: digest,
                ..
            },
        ) if profile_id == id && profile_digest == digest => Ok(()),
        _ => Err(Error::Invalid),
    }
}
