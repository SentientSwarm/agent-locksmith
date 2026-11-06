//! Native access-only view of the existing controlled custody domain.
use super::*;
use crate::registrations::AuthSpec;
use locksmith_mcp_transport::Certificate;
use secrecy::SecretString;
use sqlx::SqliteConnection;
use std::{collections::HashMap, io::Read};

pub(super) struct Roots {
    certificates: Vec<Certificate>,
    digest: String,
}
pub(crate) struct Account {
    pub version: i64,
    pub expires_at: Option<i64>,
    pub roots_digest: String,
    pub roots: Vec<Certificate>,
    pub selected_tools: Option<Vec<String>>,
}
pub(super) fn load_roots(config: &config::Config) -> Result<HashMap<String, Roots>> {
    config
        .profiles
        .iter()
        .map(|p| {
            let mut bytes = Vec::new();
            std::fs::File::open(&p.ca_path)
                .map_err(|_| Error("roots_invalid"))?
                .take(1024 * 1024 + 1)
                .read_to_end(&mut bytes)
                .map_err(|_| Error("roots_invalid"))?;
            if bytes.len() > 1024 * 1024 {
                return Err(Error("roots_invalid"));
            }
            let certificates =
                Certificate::from_pem_bundle(&bytes).map_err(|_| Error("roots_invalid"))?;
            if certificates.is_empty() {
                return Err(Error("roots_invalid"));
            }
            Ok((
                p.id.clone(),
                Roots {
                    certificates,
                    digest: digest(&bytes),
                },
            ))
        })
        .collect()
}
impl Runtime {
    /// The caller owns the transaction. This reads metadata only, including when
    /// selecting. No optional refresh token is required or decrypted.
    pub(crate) async fn native_account(
        &self,
        c: &mut SqliteConnection,
        name: &str,
        selection: &AuthSpec,
    ) -> Result<Account> {
        let AuthSpec::ControlledOauth {
            session_label,
            owner_id,
            incarnation,
            profile_id,
            profile_digest,
        } = selection
        else {
            return Err(Error("invalid_request"));
        };
        let row=sqlx::query("SELECT kind,owner_id,incarnation,profile_id,profile_digest,workspace_id,user_id,subject_json,client_auth,scope,scope_echoed,token_version,refresh_pending,degraded,access_token_expires_at FROM oauth_sessions WHERE name=? AND session_label=?")
            .bind(name).bind(session_label).fetch_optional(&mut *c).await?.ok_or(Error("not_found"))?;
        if !config::managed_kind(row.get("kind"))
            || row.get::<Option<&str>, _>("owner_id") != Some(owner_id.as_str())
        {
            return Err(Error("not_found"));
        }
        let p = self.profile(profile_id)?;
        clients::current(c, owner_id, p).await?;
        if row.get::<i64, _>("incarnation") != *incarnation
            || row.get::<&str, _>("profile_id") != profile_id
            || row.get::<&str, _>("profile_digest") != profile_digest
            || !account::profile_matches(&row, p)?
        {
            return Err(Error("source_conflict"));
        }
        store::registration(c, name, Some(p)).await?;
        let version: i64 = row.get("token_version");
        let expires_at: Option<i64> = row.get("access_token_expires_at");
        if row.get::<bool, _>("refresh_pending")
            || row.get::<bool, _>("degraded")
            || version >= i64::MAX - 1
        {
            return Err(Error("reconnect_required"));
        }
        if expires_at.is_some_and(|t| t <= now()) {
            return Err(Error("access_expired"));
        }
        let roots = self
            .native_roots
            .get(profile_id)
            .ok_or(Error("invalid_profile"))?;
        Ok(Account {
            version,
            expires_at,
            roots_digest: roots.digest.clone(),
            roots: roots.certificates.clone(),
            selected_tools: p.hosted().then(|| p.selected_tools.clone()),
        })
    }
    pub(crate) async fn native_selection(
        &self,
        c: &mut SqliteConnection,
        owner: &str,
        name: &str,
        label: &str,
        expected: &str,
    ) -> Result<AuthSpec> {
        let view = self.account_view(c, owner, name, label).await?;
        if view["state"] == "absent" {
            return Err(Error("not_found"));
        }
        if view["revision"].as_str() != Some(expected) {
            return Err(Error("source_conflict"));
        }
        let row=sqlx::query("SELECT incarnation,profile_id,profile_digest FROM oauth_sessions WHERE name=? AND session_label=? AND owner_id=? AND kind IN ('controlled_linear_v1','linear_hosted_v1','linear_hosted_fixture_v1','slack_confidential_v1','slack_confidential_fixture_v1','custom_oauth_v1')")
            .bind(name).bind(label).bind(owner).fetch_optional(&mut *c).await?.ok_or(Error("not_found"))?;
        let selection = AuthSpec::ControlledOauth {
            session_label: label.into(),
            owner_id: owner.into(),
            incarnation: row.get("incarnation"),
            profile_id: row.get("profile_id"),
            profile_digest: row.get("profile_digest"),
        };
        self.native_account(c, name, &selection).await?;
        Ok(selection)
    }
    pub(crate) async fn native_access(
        &self,
        c: &mut SqliteConnection,
        name: &str,
        selection: &AuthSpec,
    ) -> Result<SecretString> {
        self.native_account(c, name, selection).await?;
        let AuthSpec::ControlledOauth {
            session_label,
            incarnation,
            ..
        } = selection
        else {
            return Err(Error("invalid_request"));
        };
        let row=sqlx::query("SELECT access_token_ciphertext,access_token_nonce FROM oauth_sessions WHERE name=? AND session_label=? AND incarnation=?")
            .bind(name).bind(session_label).bind(incarnation).fetch_optional(&mut *c).await?.ok_or(Error("not_found"))?;
        let ct: Option<Vec<u8>> = row.get("access_token_ciphertext");
        let nonce: Option<Vec<u8>> = row.get("access_token_nonce");
        let bytes = self.key.unseal(
            &ct.ok_or(Error("sealing_failed"))?,
            &nonce.ok_or(Error("sealing_failed"))?,
        )?;
        let value = String::from_utf8(bytes).map_err(|_| Error("sealing_failed"))?;
        if value.is_empty()
            || value.len() > 8192
            || !value.bytes().all(|b| (0x21..=0x7e).contains(&b))
        {
            return Err(Error("sealing_failed"));
        }
        Ok(SecretString::from(value))
    }
}
