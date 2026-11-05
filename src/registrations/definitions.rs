//! Definition storage shares the existing operator registration database.
use super::RegistrationRepository;
use crate::definitions::{Definition, Error};

impl RegistrationRepository {
    pub async fn import_definition(&self, definition: &Definition) -> Result<bool, Error> {
        // Public repository callers traverse the same validator as raw API/CLI input.
        let canonical =
            crate::definitions::parse(definition.canonical()?.as_bytes())?.canonical()?;
        let mut tx = self.pool.begin().await?;
        let inserted = sqlx::query("INSERT INTO integration_definitions (id, revision, canonical_json, digest) VALUES (?, ?, ?, ?) ON CONFLICT(id, revision) DO NOTHING")
            .bind(&definition.id).bind(definition.revision).bind(&canonical).bind(definition.digest()?)
            .execute(&mut *tx).await?.rows_affected() == 1;
        let saved: String = sqlx::query_scalar(
            "SELECT canonical_json FROM integration_definitions WHERE id = ? AND revision = ?",
        )
        .bind(&definition.id)
        .bind(definition.revision)
        .fetch_one(&mut *tx)
        .await?;
        if saved != canonical {
            return Err(Error::Conflict);
        }
        tx.commit().await?;
        Ok(inserted)
    }
    pub async fn get_definition(&self, id: &str, revision: u32) -> Result<Definition, Error> {
        crate::definitions::validate::identity(id, revision)?;
        let saved: Option<String> = sqlx::query_scalar(
            "SELECT canonical_json FROM integration_definitions WHERE id = ? AND revision = ?",
        )
        .bind(id)
        .bind(revision)
        .fetch_optional(&self.pool)
        .await?;
        crate::definitions::parse(saved.ok_or(Error::NotFound)?.as_bytes())
            .map_err(|_| Error::Backend)
    }
}
