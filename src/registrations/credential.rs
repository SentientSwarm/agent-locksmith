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
        let mut tx = self
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(backend)?;
        let row = sqlx::query("SELECT name, kind, description, upstream, auth_json, egress, timeouts_json, body_limit_bytes, metadata_json, seed, disabled, created_at, updated_at, protocol, mcp_json, upstream_ca_pem FROM registrations WHERE name = ?")
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
        let auth = auth(expected, &reference);
        sqlx::query("UPDATE registrations SET auth_json = ?, seed = 0, updated_at = unixepoch() WHERE name = ?")
            .bind(serde_json::to_string(&auth).map_err(backend)?).bind(&expected.name)
            .execute(&mut *tx).await.map_err(backend)?;
        tx.commit().await.map_err(backend)?;
        Ok(reference)
    }
}
fn auth(existing: &Registration, reference: &str) -> AuthSpec {
    match existing.auth.header_name() {
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
