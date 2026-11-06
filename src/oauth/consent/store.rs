use super::*;
use crate::registrations::AuthSpec;
use secrecy::ExposeSecret;
use serde_json::json;
use sqlx::{SqliteConnection, sqlite::SqliteRow};

const WIPE: &str =
    "state_hash=NULL,verifier_ct=NULL,verifier_nonce=NULL,quarantine_ct=NULL,quarantine_nonce=NULL";

impl Runtime {
    pub async fn start(&self, owner: &str, name: &str, request: &Start) -> Result<Value> {
        if !identifier(name)
            || !identifier(&request.session_label)
            || request.requested_scopes != ["read"]
        {
            return Err(Error("invalid_request"));
        }
        let p = self.profile(&request.auth_profile_id)?;
        if p.client_generation != request.client_generation
            || p.redirect_profile_id != request.redirect_profile_id
        {
            return Err(Error("profile_conflict"));
        }
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        sweep(&mut tx).await?;
        let (instance, revision) = registration(&mut tx, name, Some(p)).await?;
        if revision != request.expected_config_revision {
            return Err(Error("source_conflict"));
        }
        let existing: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM oauth_sessions WHERE name=? AND session_label=?)",
        )
        .bind(name)
        .bind(&request.session_label)
        .fetch_one(&mut *tx)
        .await?;
        let active: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM oauth_consent_attempts WHERE name=? AND session_label=? AND state IN ('pending','exchanging'))")
            .bind(name).bind(&request.session_label).fetch_one(&mut *tx).await?;
        if existing || active {
            return Err(Error("account_conflict"));
        }
        let all: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM oauth_consent_attempts WHERE state IN ('pending','exchanging')",
        )
        .fetch_one(&mut *tx)
        .await?;
        let own: i64 = sqlx::query_scalar("SELECT count(*) FROM oauth_consent_attempts WHERE state IN ('pending','exchanging') AND owner_id=?").bind(owner).fetch_one(&mut *tx).await?;
        if all >= 32 || own >= 8 {
            return Err(Error("capacity"));
        }
        sqlx::query("DELETE FROM oauth_consent_attempts WHERE id IN (SELECT id FROM oauth_consent_attempts WHERE state NOT IN ('pending','exchanging') ORDER BY updated_at,id LIMIT MAX(0,(SELECT count(*) FROM oauth_consent_attempts)-127))").execute(&mut *tx).await?;
        let id = random()?;
        let state = random()?;
        let verifier: secrecy::SecretString = random()?.into();
        let (ct, nonce) = self.key.seal(verifier.expose_secret().as_bytes())?;
        let deadline = now() + 600;
        sqlx::query("INSERT INTO oauth_consent_attempts(id,state_hash,owner_id,name,session_label,instance_id,config_revision,profile_id,profile_digest,run_id,deadline,created_at,updated_at,state,verifier_ct,verifier_nonce) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,'pending',?,?)")
            .bind(&id).bind(digest(state.as_bytes())).bind(owner).bind(name).bind(&request.session_label)
            .bind(instance).bind(revision).bind(&p.id).bind(p.digest()?).bind(&self.run_id)
            .bind(deadline).bind(now()).bind(now()).bind(ct).bind(nonce).execute(&mut *tx).await?;
        let mut url =
            reqwest::Url::parse(&p.authorization_endpoint).map_err(|_| Error("invalid_profile"))?;
        url.query_pairs_mut().extend_pairs([
            ("response_type", "code"),
            ("client_id", &p.client_id),
            ("redirect_uri", &p.redirect_uri),
            ("scope", "read"),
            ("resource", &p.resource),
            ("state", &state),
            ("code_challenge_method", "S256"),
            (
                "code_challenge",
                &digest(verifier.expose_secret().as_bytes()),
            ),
        ]);
        tx.commit().await?;
        Ok(
            json!({"attempt_id":id,"state":"pending","deadline":deadline,"session_label":request.session_label,"authorization_url":url.as_str()}),
        )
    }
    pub async fn poll(&self, owner: &str, name: &str, id: &str) -> Result<Value> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        sweep(&mut tx).await?;
        let row = owned_attempt(&mut tx, owner, name, id).await?;
        let result = json!({"attempt_id":id,"state":row.get::<String,_>("state"),"deadline":row.get::<i64,_>("deadline"),
            "session_label":row.get::<String,_>("session_label"),"account_generation":row.get::<Option<i64>,_>("account_generation"),
            "safe_reason":row.get::<Option<String>,_>("reason"),"stage":row.get::<String,_>("stage"),
            "cleanup":row.get::<Option<String>,_>("cleanup"),"finalization":row.get::<Option<String>,_>("finalization")});
        tx.commit().await?;
        Ok(result)
    }
    pub async fn cancel(&self, owner: &str, name: &str, id: &str) -> Result<()> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        owned_attempt(&mut tx, owner, name, id).await?;
        terminate(&mut tx, id, "canceled", "canceled").await?;
        tx.commit().await?;
        Ok(())
    }
    pub async fn account(&self, owner: &str, name: &str, label: &str) -> Result<Value> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        sweep(&mut tx).await?;
        let result = self.account_view(&mut tx, owner, name, label).await?;
        tx.commit().await?;
        Ok(result)
    }
    pub async fn disconnect(
        &self,
        owner: &str,
        name: &str,
        label: &str,
        expected: &str,
    ) -> Result<Value> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        sweep(&mut tx).await?;
        let current = self.account_view(&mut tx, owner, name, label).await?;
        if current["revision"].as_str() != Some(expected) {
            return Err(Error("source_conflict"));
        }
        sqlx::query(&format!("UPDATE oauth_consent_attempts SET state='canceled',reason='disconnected',updated_at=?,version=version+1,{WIPE} WHERE name=? AND session_label=? AND owner_id=? AND state IN ('pending','exchanging')"))
            .bind(now()).bind(name).bind(label).bind(owner).execute(&mut *tx).await?;
        sqlx::query("DELETE FROM oauth_sessions WHERE name=? AND session_label=? AND kind='controlled_linear_v1' AND owner_id=?")
            .bind(name).bind(label).bind(owner).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(
            json!({"state":"disconnected","account_generation":current["account_generation"],"remote_revocation":"unsupported"}),
        )
    }
    pub(super) async fn claim(&self, state: &str, issuer: &str) -> Result<SqliteRow> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        sweep(&mut tx).await?;
        let row = sqlx::query("SELECT * FROM oauth_consent_attempts WHERE state_hash=? AND state='pending' AND run_id=?")
            .bind(digest(state.as_bytes())).bind(&self.run_id).fetch_optional(&mut *tx).await?.ok_or(Error("callback_refused"))?;
        let p = self.profile(row.get("profile_id"))?;
        if p.issuer != issuer {
            return Err(Error("callback_refused"));
        }
        current(&mut tx, &row, p, &self.run_id, "pending").await?;
        let id: &str = row.get("id");
        let claimed = sqlx::query("UPDATE oauth_consent_attempts SET state='exchanging',state_hash=NULL,version=version+1,stage='claimed',updated_at=? WHERE id=? AND state='pending' RETURNING *")
            .bind(now()).bind(id).fetch_one(&mut *tx).await?;
        tx.commit().await?;
        Ok(claimed)
    }
    pub(super) async fn check(&self, attempt: &SqliteRow) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        let live = sqlx::query("SELECT * FROM oauth_consent_attempts WHERE id=?")
            .bind(attempt.get::<&str, _>("id"))
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(Error("attempt_changed"))?;
        if live.get::<i64, _>("version") != attempt.get::<i64, _>("version") {
            return Err(Error("attempt_changed"));
        }
        current(
            &mut tx,
            &live,
            self.profile(live.get("profile_id"))?,
            &self.run_id,
            "exchanging",
        )
        .await
    }
    pub(super) async fn quarantine(&self, a: &SqliteRow, token: &token::Token) -> Result<()> {
        let encoded = token.encode();
        let (ct, n) = self.key.seal(encoded.expose_secret().as_bytes())?;
        let result = sqlx::query("UPDATE oauth_consent_attempts SET quarantine_ct=?,quarantine_nonce=?,verifier_ct=NULL,verifier_nonce=NULL WHERE id=? AND version=? AND state='exchanging' AND deadline>?")
            .bind(ct).bind(n).bind(a.get::<&str,_>("id")).bind(a.get::<i64,_>("version")).bind(now()).execute(&self.pool).await?;
        if result.rows_affected() != 1 {
            return Err(Error("attempt_changed"));
        }
        Ok(())
    }
    pub(super) async fn publish(&self, a: &SqliteRow, token: &token::Token) -> Result<i64> {
        let p = self.profile(a.get("profile_id"))?;
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let live = sqlx::query("SELECT * FROM oauth_consent_attempts WHERE id=?")
            .bind(a.get::<&str, _>("id"))
            .fetch_one(&mut *tx)
            .await?;
        if live.get::<i64, _>("version") != a.get::<i64, _>("version") {
            return Err(Error("attempt_changed"));
        }
        current(&mut tx, &live, p, &self.run_id, "exchanging").await?;
        let count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM oauth_sessions WHERE kind='controlled_linear_v1'",
        )
        .fetch_one(&mut *tx)
        .await?;
        if count >= 128 {
            return Err(Error("capacity"));
        }
        let (access, an) = self.key.seal(token.access.expose_secret().as_bytes())?;
        let refresh = token
            .refresh
            .as_ref()
            .map(|t| self.key.seal(t.expose_secret().as_bytes()))
            .transpose()?;
        sqlx::query(&format!("UPDATE oauth_consent_attempts SET state='connected',updated_at=?,stage='committed',reason=NULL,{WIPE} WHERE id=?"))
            .bind(now()).bind(a.get::<&str,_>("id")).execute(&mut *tx).await?;
        let inserted = sqlx::query("INSERT INTO oauth_sessions(name,session_label,kind,owner_id,profile_id,profile_digest,workspace_id,user_id,access_token_ciphertext,access_token_nonce,refresh_token_ciphertext,refresh_token_nonce,access_token_expires_at,scope,scope_echoed,created_at,updated_at) VALUES(?,?,'controlled_linear_v1',?,?,?,?,?,?,?,?,?,?,?,?,?,?) RETURNING *")
            .bind(a.get::<&str,_>("name")).bind(a.get::<&str,_>("session_label")).bind(a.get::<&str,_>("owner_id"))
            .bind(&p.id).bind(p.digest()?).bind(&p.expected_workspace).bind(&p.expected_user)
            .bind(access).bind(an).bind(refresh.as_ref().map(|x| &x.0)).bind(refresh.as_ref().map(|x| &x.1))
            .bind(token.expiry).bind(if token.scope_echoed {"read"} else {""}).bind(token.scope_echoed)
            .bind(now()).bind(now()).fetch_one(&mut *tx).await?;
        // Verify the inserted custody before COMMIT, including nullable refresh.
        let decoded = self.key.unseal(
            inserted.get("access_token_ciphertext"),
            inserted.get("access_token_nonce"),
        )?;
        if decoded != token.access.expose_secret().as_bytes() {
            return Err(Error("sealing_failed"));
        }
        if let Some(expected) = &token.refresh {
            let decoded = self.key.unseal(
                inserted.get("refresh_token_ciphertext"),
                inserted.get("refresh_token_nonce"),
            )?;
            if decoded != expected.expose_secret().as_bytes() {
                return Err(Error("sealing_failed"));
            }
        }
        let generation: i64 = inserted.get("incarnation");
        sqlx::query("UPDATE oauth_consent_attempts SET account_generation=? WHERE id=?")
            .bind(generation)
            .bind(a.get::<&str, _>("id"))
            .execute(&mut *tx)
            .await?;
        #[cfg(test)]
        crate::oauth::refresh::recovery_barrier::reach("consent_decoded").await;
        if now() >= a.get::<i64, _>("deadline") {
            return Err(Error("expired"));
        }
        tx.commit().await.map_err(|_| Error("commit_unknown"))?;
        Ok(generation)
    }
    pub(super) async fn fail(
        &self,
        id: &str,
        stage: &'static str,
        reason: &'static str,
    ) -> Result<()> {
        sqlx::query(&format!("UPDATE oauth_consent_attempts SET state='failed',stage=?,reason=?,updated_at=?,version=version+1,{WIPE} WHERE id=? AND state IN ('pending','exchanging')"))
            .bind(stage).bind(reason).bind(now()).bind(id).execute(&self.pool).await?;
        Ok(())
    }
    pub(super) async fn diagnostics(
        &self,
        id: &str,
        cleanup: &'static str,
        finalization: &'static str,
    ) -> Result<()> {
        sqlx::query("UPDATE oauth_consent_attempts SET cleanup=?,finalization=? WHERE id=?")
            .bind(cleanup)
            .bind(finalization)
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
    pub(super) async fn sweep(&self) -> Result<()> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        sweep(&mut tx).await?;
        tx.commit().await?;
        Ok(())
    }
}
async fn sweep(c: &mut SqliteConnection) -> Result<()> {
    sqlx::query(&format!("UPDATE oauth_consent_attempts SET state='expired',reason=COALESCE(reason,'expired'),updated_at=?,version=version+1,{WIPE} WHERE state IN ('pending','exchanging') AND deadline<=?"))
        .bind(now()).bind(now()).execute(&mut *c).await?;
    sqlx::query("DELETE FROM oauth_consent_attempts WHERE state NOT IN ('pending','exchanging') AND updated_at<?").bind(now()-86400).execute(c).await?;
    Ok(())
}
async fn terminate(c: &mut SqliteConnection, id: &str, state: &str, reason: &str) -> Result<()> {
    sqlx::query(&format!("UPDATE oauth_consent_attempts SET state=?,reason=?,updated_at=?,version=version+1,{WIPE} WHERE id=? AND state IN ('pending','exchanging')"))
        .bind(state).bind(reason).bind(now()).bind(id).execute(c).await?;
    Ok(())
}
async fn owned_attempt(
    c: &mut SqliteConnection,
    owner: &str,
    name: &str,
    id: &str,
) -> Result<SqliteRow> {
    sqlx::query("SELECT * FROM oauth_consent_attempts WHERE id=? AND name=? AND owner_id=?")
        .bind(id)
        .bind(name)
        .bind(owner)
        .fetch_optional(c)
        .await?
        .ok_or(Error("not_found"))
}
pub(super) async fn registration(
    c: &mut SqliteConnection,
    name: &str,
    profile: Option<&config::Profile>,
) -> Result<(String, i64)> {
    let row = sqlx::query("SELECT r.*,i.instance_id,i.revision FROM registrations r JOIN registration_instances i USING(name) WHERE r.name=?")
        .bind(name).fetch_optional(&mut *c).await?.ok_or(Error("not_found"))?;
    if let Some(p) = profile {
        let auth: AuthSpec =
            serde_json::from_str(row.get("auth_json")).map_err(|_| Error("profile_conflict"))?;
        let expected = p.auth_spec();
        let r = crate::registrations::repo::row_to_registration_ref(&row)
            .map_err(|_| Error("profile_conflict"))?;
        crate::definitions::eligibility::selected(c, &r, None)
            .await
            .map_err(|_| Error("profile_conflict"))?;
        if r.definition_pinned() {
            let Some(crate::definitions::Activation::ControlledOauth {
                profile_id,
                profile_digest,
            }) = r
                .mcp
                .as_ref()
                .and_then(|m| m.definition_activation.as_ref())
            else {
                return Err(Error("profile_conflict"));
            };
            if profile_id != &p.id || profile_digest != &p.digest()? {
                return Err(Error("profile_conflict"));
            }
        }
        if auth != expected
            || !native_registration_or_http(&row)
            || row.get::<&str, _>("kind") != "tool"
            || row.get::<&str, _>("upstream") != p.resource
        {
            return Err(Error("profile_conflict"));
        }
    }
    Ok((row.get("instance_id"), row.get("revision")))
}
async fn current(
    c: &mut SqliteConnection,
    a: &SqliteRow,
    p: &config::Profile,
    run: &str,
    state: &str,
) -> Result<()> {
    if a.get::<&str, _>("state") != state
        || a.get::<&str, _>("run_id") != run
        || a.get::<i64, _>("deadline") <= now()
        || a.get::<&str, _>("profile_digest") != p.digest()?
    {
        return Err(Error("attempt_changed"));
    }
    let (instance, revision) = registration(c, a.get("name"), Some(p)).await?;
    if instance != a.get::<&str, _>("instance_id") || revision != a.get::<i64, _>("config_revision")
    {
        return Err(Error("source_conflict"));
    }
    Ok(())
}

// Preserve the legacy HTTP profile predicate; native consent additionally uses
// the existing manual/direct/HTTPS configuration validator.
fn native_registration_or_http(row: &SqliteRow) -> bool {
    use crate::registrations::{Kind, McpConfig, Protocol, protocol};
    if row.get::<&str, _>("protocol") == "http" {
        return row.get::<Option<String>, _>("mcp_json").is_none();
    }
    let Some(raw) = row.get::<Option<&str>, _>("mcp_json") else {
        return false;
    };
    let Ok(config) = serde_json::from_str::<McpConfig>(raw) else {
        return false;
    };
    let Ok(metadata) = serde_json::from_str::<Value>(row.get("metadata_json")) else {
        return false;
    };
    !row.get::<bool, _>("disabled")
        && !row.get::<bool, _>("seed")
        && row.get::<&str, _>("egress") == "direct"
        && protocol::validate(
            Protocol::McpStreamableHttp,
            Some(&config),
            Kind::Tool,
            crate::config::EgressMode::Direct,
            row.get("upstream"),
            Some(&metadata),
        )
        .is_ok()
}
