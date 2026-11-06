use super::store::registration;
use super::*;
use serde_json::json;
use sqlx::{SqliteConnection, sqlite::SqliteRow};

impl Runtime {
    pub(super) async fn account_view(
        &self,
        c: &mut SqliteConnection,
        owner: &str,
        name: &str,
        label: &str,
    ) -> Result<Value> {
        if !identifier(name) || !identifier(label) {
            return Err(Error("invalid_request"));
        }
        let row = sqlx::query("SELECT incarnation,kind,owner_id,profile_id,profile_digest,workspace_id,user_id,token_version,refresh_pending,degraded,access_token_expires_at,scope,scope_echoed,refresh_token_ciphertext IS NOT NULL AS has_refresh FROM oauth_sessions WHERE name=? AND session_label=?")
            .bind(name).bind(label).fetch_optional(&mut *c).await?;
        if let Some(row) = row {
            if !config::managed_kind(row.get("kind"))
                || row.get::<Option<&str>, _>("owner_id") != Some(owner)
            {
                return Err(Error("not_found"));
            }
            let registration = match registration(c, name, None).await {
                Ok(value) => Some(value),
                Err(Error("not_found")) => None,
                Err(e) => return Err(e),
            };
            let profile = self.profile(row.get("profile_id")).ok();
            let profile_digest = profile.map(config::Profile::digest).transpose()?;
            let compatible = if let Some(profile) = profile {
                if !profile_matches(&row, profile)?
                    || clients::current(c, owner, profile).await.is_err()
                {
                    false
                } else {
                    match super::store::registration(c, name, Some(profile)).await {
                        Ok(_) => true,
                        Err(Error("not_found" | "profile_conflict")) => false,
                        Err(e) => return Err(e),
                    }
                }
            } else {
                false
            };
            let pending: bool = row.get("refresh_pending");
            let degraded: bool = row.get("degraded");
            let has_refresh: bool = row.get("has_refresh");
            let version: i64 = row.get("token_version");
            let expired = row
                .get::<Option<i64>, _>("access_token_expires_at")
                .is_some_and(|t| t <= now());
            let exhausted = version >= i64::MAX - 1;
            let reconnect = pending
                || degraded
                || registration.is_none()
                || !compatible
                || exhausted
                || (expired && !has_refresh);
            let reason = if pending {
                Some("refresh_pending")
            } else if degraded {
                Some("account_degraded")
            } else if registration.is_none() {
                Some("registration_unavailable")
            } else if !compatible {
                Some("profile_conflict")
            } else if !has_refresh {
                Some("refresh_missing")
            } else if exhausted {
                Some("version_exhausted")
            } else {
                None
            };
            let generation: i64 = row.get("incarnation");
            let revision = digest(
                serde_json::to_vec(&json!([
                    2,
                    owner,
                    name,
                    label,
                    generation,
                    version,
                    pending,
                    degraded,
                    row.get::<&str, _>("profile_id"),
                    row.get::<&str, _>("profile_digest"),
                    profile_digest,
                    registration
                ]))
                .unwrap()
                .as_slice(),
            );
            return Ok(
                json!({"state":if reconnect {"reconnect_required"} else {"connected_unbound"},"kind":row.get::<&str,_>("kind"),"profile":row.get::<&str,_>("profile_id"),"account_generation":generation,"revision":revision,
                "config_revision":registration.as_ref().map(|r| r.1),"token_expires_at":row.get::<Option<i64>,_>("access_token_expires_at"),"identity_verified":true,"requested_scopes":requested_scopes(row.get("kind")),"granted_scope":row.get::<bool,_>("scope_echoed").then(|| row.get::<&str,_>("scope")),
                "token_version":version,"refresh_pending":pending,"reconnect_required":reconnect,"refresh_available":reason.is_none(),"refresh_unavailable_reason":reason}),
            );
        }
        let (instance, revision) = registration(c, name, None).await?;
        let active = sqlx::query("SELECT id,owner_id FROM oauth_consent_attempts WHERE name=? AND session_label=? AND state IN ('pending','exchanging')")
        .bind(name).bind(label).fetch_optional(c).await?;
        if active
            .as_ref()
            .is_some_and(|a| a.get::<&str, _>("owner_id") != owner)
        {
            return Err(Error("not_found"));
        }
        let id = active.as_ref().map(|a| a.get::<&str, _>("id"));
        Ok(
            json!({"state":"absent","config_revision":revision,"account_generation":null,"revision":digest(serde_json::to_string(&json!([instance,revision,label,id])).unwrap().as_bytes())}),
        )
    }
}

pub(super) fn profile_matches(row: &SqliteRow, p: &config::Profile) -> Result<bool> {
    Ok(row.get::<&str, _>("kind") == p.stored_kind()
        && row.get::<&str, _>("profile_digest") == p.digest()?
        && row.get::<&str, _>("workspace_id") == p.expected_workspace
        && row.get::<&str, _>("user_id") == p.expected_user)
}

// Managed kinds have fixed requested scopes; current config may be removed/replaced.
fn requested_scopes(kind: &str) -> Vec<&'static str> {
    if matches!(
        kind,
        "slack_confidential_v1" | "slack_confidential_fixture_v1"
    ) {
        super::slack::SCOPES.to_vec()
    } else {
        vec!["read"]
    }
}
