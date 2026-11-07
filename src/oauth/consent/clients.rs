//! Immutable confidential-client bindings in the existing sealed credential store.
use super::*;
use secrecy::SecretString;
use sqlx::{SqliteConnection, sqlite::SqliteRow};

pub(super) async fn current(
    c: &mut SqliteConnection,
    owner: &str,
    p: &config::Profile,
) -> Result<()> {
    if p.confidential() {
        row(c, owner, p).await?;
    }
    Ok(())
}

async fn row(c: &mut SqliteConnection, owner: &str, p: &config::Profile) -> Result<SqliteRow> {
    sqlx::query("SELECT s.sealed_value,s.nonce FROM oauth_consent_clients c JOIN credential_secrets s USING(secret_ref) WHERE c.owner_id=? AND c.profile_id=? AND c.client_generation=? AND c.profile_digest=? AND c.retired_at IS NULL AND s.tombstoned_at IS NULL")
        .bind(owner).bind(&p.id).bind(p.client_generation as i64).bind(p.digest()?)
        .fetch_optional(c).await?.ok_or(Error("client_unavailable"))
}

impl Runtime {
    pub(super) async fn resolve_client(
        &self,
        c: &mut SqliteConnection,
        owner: &str,
        p: &config::Profile,
    ) -> Result<Option<SecretString>> {
        if !p.confidential() {
            return Ok(None);
        }
        let key = self
            .client_key
            .as_ref()
            .ok_or(Error("client_unavailable"))?;
        let row = row(c, owner, p).await?;
        let clear = String::from_utf8(key.unseal(row.get("sealed_value"), row.get("nonce"))?)
            .map_err(|_| Error("client_unavailable"))?;
        token::secret(&Value::String(clear)).map(Some)
    }

    pub(super) async fn client_for_attempt(&self, a: &SqliteRow) -> Result<Option<SecretString>> {
        let mut c = self.pool.acquire().await?;
        self.resolve_client(
            &mut c,
            a.get("owner_id"),
            self.profile(a.get("profile_id"))?,
        )
        .await
    }

    pub(super) async fn set_client(
        &self,
        owner: &str,
        name: &str,
        profile: &str,
        generation: u64,
        value: &str,
    ) -> Result<Value> {
        let p = self.client_profile(profile, generation)?;
        let (ct, nonce) = self.seal_client(value)?;
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        store::registration(&mut tx, name, Some(p)).await?;
        let highest: Option<i64> = sqlx::query_scalar("SELECT MAX(client_generation) FROM oauth_consent_clients WHERE owner_id=? AND profile_id=?")
            .bind(owner).bind(profile).fetch_one(&mut *tx).await?;
        if highest.is_some_and(|n| n >= generation as i64) {
            return Err(Error("client_generation_conflict"));
        }
        sqlx::query("UPDATE oauth_consent_clients SET retired_at=? WHERE owner_id=? AND profile_id=? AND retired_at IS NULL").bind(now()).bind(owner).bind(profile).execute(&mut *tx).await?;
        let reference = crate::repo::CredentialSecretsRepository::insert_into(&mut tx, &ct, &nonce)
            .await
            .map_err(|_| Error("custody_failed"))?;
        sqlx::query("INSERT INTO oauth_consent_clients(owner_id,profile_id,client_generation,profile_digest,secret_ref,created_at) VALUES(?,?,?,?,?,?)")
            .bind(owner).bind(profile).bind(generation as i64).bind(p.digest()?).bind(reference).bind(now()).execute(&mut *tx).await?;
        self.resolve_client(&mut tx, owner, p).await?;
        tx.commit().await?;
        Ok(
            serde_json::json!({"profile":profile,"client_generation":generation,"state":"configured"}),
        )
    }

    fn seal_client(&self, value: &str) -> Result<(Vec<u8>, Vec<u8>)> {
        let key = self
            .client_key
            .as_ref()
            .ok_or(Error("client_unavailable"))?;
        let secret = token::secret(&Value::String(value.into()))?;
        use secrecy::ExposeSecret;
        Ok(key.seal(secret.expose_secret().as_bytes())?)
    }

    pub(super) fn client_profile(&self, id: &str, generation: u64) -> Result<&config::Profile> {
        let p = self.profile(id)?;
        if !p.confidential() || p.client_generation != generation {
            return Err(Error("profile_conflict"));
        }
        Ok(p)
    }
}
