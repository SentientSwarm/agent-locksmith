use super::{
    Error, Result, destination,
    runtime::Runtime,
    source::{Current, Source},
    store, wire,
};
use crate::registrations::AuthSpec;
use secrecy::{ExposeSecret, SecretString};
use serde_json::Value;
use sqlx::Row;

impl Runtime {
    pub async fn observe(
        &self,
        agent: &str,
        name: &str,
        expected: &Source,
        generation: Option<&str>,
    ) -> Result<Value> {
        let mut tx = self.repo.pool.begin().await?;
        let current = self.current(&mut tx, agent, name).await?;
        current.matches(expected)?;
        let generation = store::reserve(&mut tx, &current, &self.run, generation).await?;
        tx.commit().await?;
        let result = self.collect(agent, name, &current).await;
        self.finish(agent, name, expected, &generation, result)
            .await?;
        self.snapshot(agent, name).await
    }
    async fn collect(&self, agent: &str, name: &str, current: &Current) -> Result<Value> {
        let reg = &current.admission.registration;
        let private = reg
            .mcp
            .as_ref()
            .is_some_and(|c| c.allow_private_destination);
        let addresses = destination::resolve(&reg.upstream, private, &self.listeners).await?;
        let bearer = self.materialize(agent, name, &current.source).await?;
        let client = locksmith_mcp_transport::Client::pinned(
            Default::default(),
            self.roots.clone(),
            &reg.upstream,
            addresses,
            1024 * 1024,
            wire::validate,
        )
        .map_err(|_| Error("upstream_client"))?;
        let mut connection = wire::Connection {
            client,
            endpoint: reg.upstream.clone().into(),
            bearer: bearer.as_ref().map(ExposeSecret::expose_secret),
            session: None,
        };
        let result = connection.observe().await;
        // No background cleanup: a stalled DELETE shares the enclosing deadline.
        connection.cleanup().await;
        result
    }
    async fn materialize(
        &self,
        agent: &str,
        name: &str,
        expected: &Source,
    ) -> Result<Option<SecretString>> {
        let mut tx = self.repo.pool.begin().await?;
        let current = self.current(&mut tx, agent, name).await?;
        current.matches(expected)?;
        let secret = match current.admission.account.as_ref() {
            Some(AuthSpec::None) => None,
            Some(AuthSpec::StoredBearer { secret_ref }) => {
                let row = sqlx::query("SELECT sealed_value,nonce FROM credential_secrets WHERE secret_ref=? AND tombstoned_at IS NULL")
                    .bind(secret_ref).fetch_optional(&mut *tx).await?.ok_or(Error("credential_unresolved"))?;
                Some(unseal(
                    self.key.as_ref(),
                    row.get("sealed_value"),
                    row.get("nonce"),
                )?)
            }
            _ => return Err(Error("native_account_unsupported")),
        };
        tx.commit().await?;
        Ok(secret)
    }
    async fn finish(
        &self,
        agent: &str,
        name: &str,
        expected: &Source,
        generation: &str,
        result: Result<Value>,
    ) -> Result<()> {
        let mut tx = self.repo.pool.begin().await?;
        match result {
            Ok(manifest) => {
                let current = self.current(&mut tx, agent, name).await?;
                current.matches(expected)?;
                store::publish(&mut tx, &current, generation, &manifest).await?;
                tx.commit().await?;
                Ok(())
            }
            Err(error) => {
                store::failed(&mut tx, expected, generation).await?;
                tx.commit().await?;
                Err(error)
            }
        }
    }
}
fn unseal(
    key: Option<&crate::secret::CredentialSealingKey>,
    sealed: Vec<u8>,
    nonce: Vec<u8>,
) -> Result<SecretString> {
    let bytes = key
        .ok_or(Error("credential_unresolved"))?
        .unseal(&sealed, &nonce)
        .map_err(|_| Error("credential_unresolved"))?;
    let text = String::from_utf8(bytes).map_err(|_| Error("credential_unresolved"))?;
    let valid =
        !text.is_empty() && text.len() <= 8192 && text.bytes().all(|b| (0x21..=0x7e).contains(&b));
    let secret = SecretString::from(text);
    if valid {
        Ok(secret)
    } else {
        Err(Error("credential_unresolved"))
    }
}
