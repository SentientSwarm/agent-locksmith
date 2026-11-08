use super::*;
impl Runtime {
    pub(in crate::oauth::consent) async fn claim_refresh(
        &self,
        owner: &str,
        name: &str,
        label: &str,
        expected: &str,
        deadline: Instant,
        trace: &mut Trace,
    ) -> Result<Claim> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let view = self.account_view(&mut tx, owner, name, label).await?;
        if view["state"] == "absent" {
            return Err(Error("not_found"));
        }
        if view["revision"].as_str() != Some(expected) {
            return Err(Error("source_conflict"));
        }
        match view["refresh_unavailable_reason"].as_str() {
            Some("refresh_pending" | "account_degraded") => {
                return Err(Error("reconnect_required"));
            }
            Some("version_exhausted") => return Err(Error("version_exhausted")),
            Some("refresh_missing") => return Err(Error("refresh_unavailable")),
            Some(_) => return Err(Error("profile_conflict")),
            None => {}
        }
        let row = sqlx::query("SELECT * FROM oauth_sessions WHERE name=? AND session_label=?")
            .bind(name)
            .bind(label)
            .fetch_one(&mut *tx)
            .await?;
        let profile = self.profile(row.get("profile_id"))?;
        // Deterministic TLS construction occurs before the durable claim.
        let token_client = token::client(profile)?;
        let wire_client = wire::client(profile)?;
        let old = self.decode_custody(&row)?;
        if old.refresh.is_none() {
            return Err(Error("refresh_unavailable"));
        }
        let version: i64 = row.get("token_version");
        if version >= i64::MAX - 1 {
            return Err(Error("version_exhausted"));
        }
        let claim = Claim {
            owner: owner.into(),
            name: name.into(),
            label: label.into(),
            generation: row.get("incarnation"),
            version: version + 1,
            profile_id: profile.id.clone(),
            profile_digest: profile.digest()?,
            registration: store::registration(&mut tx, name, Some(profile)).await?,
            token_client,
            wire_client,
            old,
            deadline,
        };
        let updated = sqlx::query("UPDATE oauth_sessions SET refresh_pending=1,token_version=token_version+1,updated_at=? WHERE incarnation=? AND token_version=? AND kind='controlled_linear_v1' AND owner_id=? AND refresh_pending=0 AND degraded=0 RETURNING *")
            .bind(now()).bind(claim.generation).bind(version).bind(owner).fetch_optional(&mut *tx).await?.ok_or(Error("source_conflict"))?;
        if updated.get::<i64, _>("token_version") != claim.version
            || !updated.get::<bool, _>("refresh_pending")
        {
            return Err(Error("custody_failed"));
        }
        let decoded = self.decode_custody(&updated)?;
        compare(&claim.old, &decoded)?;
        self.current_refresh(&mut tx, &claim).await?;
        trace.enter("claim");
        trace.finalization = "commit_unknown";
        tx.commit().await.map_err(|_| Error("commit_unknown"))?;
        trace.finalization = "pending";
        Ok(claim)
    }
    pub(in crate::oauth::consent) async fn complete_refresh(
        &self,
        claim: &Claim,
        token: &token::Token,
        trace: &mut Trace,
    ) -> Result<Value> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        self.current_refresh(&mut tx, claim).await?;
        let (access, an) = self.key.seal(token.access.expose_secret().as_bytes())?;
        let refresh = token.refresh.as_ref().ok_or(Error("custody_failed"))?;
        let (refresh, rn) = self.key.seal(refresh.expose_secret().as_bytes())?;
        let updated = sqlx::query("UPDATE oauth_sessions SET access_token_ciphertext=?,access_token_nonce=?,refresh_token_ciphertext=?,refresh_token_nonce=?,access_token_expires_at=?,scope=?,scope_echoed=?,refresh_pending=0,degraded=0,token_version=token_version+1,updated_at=? WHERE incarnation=? AND token_version=? AND kind='controlled_linear_v1' AND owner_id=? AND refresh_pending=1 RETURNING *")
            .bind(access).bind(an).bind(refresh).bind(rn).bind(token.expiry).bind(if token.scope_echoed {"read"} else {""}).bind(token.scope_echoed).bind(now())
            .bind(claim.generation).bind(claim.version).bind(&claim.owner).fetch_optional(&mut *tx).await?.ok_or(Error("source_conflict"))?;
        compare(token, &self.decode_custody(&updated)?)?;
        if updated.get::<i64, _>("token_version") != claim.version + 1
            || updated.get::<bool, _>("refresh_pending")
        {
            return Err(Error("custody_failed"));
        }
        let view = self
            .account_view(&mut tx, &claim.owner, &claim.name, &claim.label)
            .await?;
        if view["token_version"] != claim.version + 1 || view["refresh_pending"] != false {
            return Err(Error("custody_failed"));
        }
        #[cfg(test)]
        crate::oauth::refresh::recovery_barrier::reach("controlled_decoded").await;
        if Instant::now() >= claim.deadline {
            return Err(Error("operation_incomplete"));
        }
        trace.finalization = "commit_unknown";
        tx.commit().await.map_err(|_| Error("commit_unknown"))?;
        #[cfg(test)]
        crate::oauth::refresh::recovery_barrier::reach("controlled_committed").await;
        trace.finalization = "committed";
        Ok(view)
    }
    fn decode_custody(&self, row: &SqliteRow) -> Result<token::Token> {
        let decode = |ct: &str, nonce: &str| -> Result<Option<secrecy::SecretString>> {
            let ct: Option<Vec<u8>> = row.try_get(ct)?;
            let nonce: Option<Vec<u8>> = row.try_get(nonce)?;
            match (ct, nonce) {
                (Some(ct), Some(nonce)) => {
                    let clear = String::from_utf8(self.key.unseal(&ct, &nonce)?)
                        .map_err(|_| Error("sealing_failed"))?;
                    token::secret(&Value::String(clear)).map(Some)
                }
                (None, None) => Ok(None),
                _ => Err(Error("sealing_failed")),
            }
        };
        Ok(token::Token {
            access: decode("access_token_ciphertext", "access_token_nonce")?
                .ok_or(Error("sealing_failed"))?,
            refresh: decode("refresh_token_ciphertext", "refresh_token_nonce")?,
            expiry: row.try_get("access_token_expires_at")?,
            scope_echoed: row.try_get("scope_echoed")?,
        })
    }
}
fn compare(expected: &token::Token, actual: &token::Token) -> Result<()> {
    if expected.access.expose_secret() != actual.access.expose_secret()
        || expected.refresh.as_ref().map(|s| s.expose_secret())
            != actual.refresh.as_ref().map(|s| s.expose_secret())
        || expected.expiry != actual.expiry
        || expected.scope_echoed != actual.scope_echoed
    {
        return Err(Error("sealing_failed"));
    }
    Ok(())
}
