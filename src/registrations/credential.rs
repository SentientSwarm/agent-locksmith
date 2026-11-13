//! Seal storage and registration attachment commit together, including refusal.
use super::{AuthSpec, Registration, RegistrationError, RegistrationRepository};
use crate::repo::CredentialSecretsRepository;

impl RegistrationRepository {
    pub async fn store_credential(
        &self,
        expected: &Registration,
        sealed: &[u8],
        nonce: &[u8],
    ) -> Result<String, RegistrationError> {
        self.store_credential_as(expected, sealed, nonce, None)
            .await
    }

    /// As [`Self::store_credential`], sending the value in `header` when
    /// given (a `stored_header` key) instead of the route's current shape.
    pub async fn store_credential_as(
        &self,
        expected: &Registration,
        sealed: &[u8],
        nonce: &[u8],
        header: Option<&str>,
    ) -> Result<String, RegistrationError> {
        let mut tx = self
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(backend)?;
        let row = sqlx::query("SELECT name, kind, description, upstream, auth_json, egress, timeouts_json, body_limit_bytes, metadata_json, seed, disabled, created_at, updated_at, protocol, mcp_json, upstream_ca_pem, profile, broker_json FROM registrations WHERE name = ?")
            .bind(&expected.name).fetch_optional(&mut *tx).await.map_err(backend)?;
        let current = row
            .map(super::repo::row_to_registration)
            .transpose()?
            .ok_or_else(|| backend("registration changed"))?;
        if current.definition_pinned() {
            return Err(RegistrationError::DefinitionPending);
        }
        if current != *expected {
            return Err(backend("registration changed"));
        }
        let reference = CredentialSecretsRepository::insert_into(&mut tx, sealed, nonce)
            .await
            .map_err(backend)?;
        let auth = stored_auth(header.or(expected.auth.header_name()), &reference);
        sqlx::query("UPDATE registrations SET auth_json = ?, seed = 0, updated_at = unixepoch() WHERE name = ?")
            .bind(serde_json::to_string(&auth).map_err(backend)?).bind(&expected.name)
            .execute(&mut *tx).await.map_err(backend)?;
        tx.commit().await.map_err(backend)?;
        Ok(reference)
    }
}
/// The stored shape a sealed value takes: a named header, else a bearer.
pub(crate) fn stored_auth(header: Option<&str>, reference: &str) -> AuthSpec {
    match header {
        Some(header) => AuthSpec::StoredHeader {
            header: header.into(),
            secret_ref: reference.into(),
        },
        None => AuthSpec::StoredBearer {
            secret_ref: reference.into(),
        },
    }
}
fn backend(e: impl std::fmt::Display) -> RegistrationError {
    RegistrationError::Backend(e.to_string())
}
