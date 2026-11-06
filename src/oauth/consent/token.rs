use super::*;
use secrecy::{ExposeSecret, SecretString};
use serde_json::json;
use std::time::Duration;

pub(super) struct Token {
    pub access: SecretString,
    pub refresh: Option<SecretString>,
    pub expiry: Option<i64>,
    pub scope_echoed: bool,
    pub granted_scope: Option<String>,
}
impl Token {
    pub fn encode(&self) -> SecretString {
        json!({"access":self.access.expose_secret(),"refresh":self.refresh.as_ref().map(|t| t.expose_secret()),"expiry":self.expiry,"scope_echoed":self.scope_echoed,"granted_scope":self.granted_scope}).to_string().into()
    }
    pub fn screen(&self, value: &Value) -> Result<()> {
        fn contains(v: &Value, secret: &str) -> bool {
            match v {
                Value::String(s) => s.contains(secret),
                Value::Array(a) => a.iter().any(|v| contains(v, secret)),
                Value::Object(o) => o
                    .iter()
                    .any(|(k, v)| k.contains(secret) || contains(v, secret)),
                _ => false,
            }
        }
        if contains(value, self.access.expose_secret())
            || self
                .refresh
                .as_ref()
                .is_some_and(|s| contains(value, s.expose_secret()))
        {
            return Err(Error("secret_echo"));
        }
        Ok(())
    }
}
pub(super) fn roots(p: &config::Profile) -> Result<Vec<u8>> {
    use std::io::Read;
    let mut bytes = Vec::new();
    std::fs::File::open(&p.ca_path)
        .map_err(|_| Error("tls_unavailable"))?
        .take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Error("tls_unavailable"))?;
    if bytes.len() > 1024 * 1024 {
        return Err(Error("tls_unavailable"));
    }
    Ok(bytes)
}
pub(super) fn client(p: &config::Profile) -> Result<reqwest::Client> {
    let mut b = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(
            if p.hosted() || p.slack() || p.custom() {
                30
            } else {
                5
            },
        ))
        .connect_timeout(Duration::from_secs(3));
    for c in
        reqwest::Certificate::from_pem_bundle(&roots(p)?).map_err(|_| Error("tls_unavailable"))?
    {
        b = b.add_root_certificate(c);
    }
    b.build().map_err(|_| Error("tls_unavailable"))
}
pub(super) async fn exchange(
    p: &config::Profile,
    code: &str,
    verifier: &str,
    client_secret: Option<&str>,
) -> Result<Token> {
    let mut form = vec![
        ("grant_type", "authorization_code"),
        ("client_id", &p.client_id),
        ("redirect_uri", &p.redirect_uri),
        ("resource", &p.resource),
        ("code", code),
        ("code_verifier", verifier),
    ];
    confidential(p, client_secret, &mut form)?;
    let (status, bytes) = super::token_io::post(p, &client(p)?, &form).await?;
    if status != reqwest::StatusCode::OK {
        return Err(Error("token_http_refused"));
    }
    super::token_io::checked_decode(p, &bytes, client_secret)
}
pub(super) fn secret(v: &Value) -> Result<SecretString> {
    v.as_str()
        .filter(|s| {
            !s.is_empty() && s.len() <= 8192 && s.bytes().all(|b| (0x21..=0x7e).contains(&b))
        })
        .map(|s| s.to_owned().into())
        .ok_or(Error("token_invalid"))
}
pub(super) fn decode(p: &config::Profile, bytes: &[u8]) -> Result<Token> {
    let v = parse(bytes)?;
    if p.custom() {
        return super::contract::decode(p, &v);
    }
    if p.slack() {
        return super::slack_token::decode(p, &v);
    }
    if !v.is_object()
        || v["token_type"]
            .as_str()
            .is_none_or(|s| !s.eq_ignore_ascii_case("Bearer"))
    {
        return Err(Error("token_invalid"));
    }
    if ["error", "error_description", "error_uri"]
        .iter()
        .any(|k| v.get(k).is_some())
    {
        return Err(Error("token_error_response"));
    }
    let access = secret(&v["access_token"])?;
    let refresh = v.get("refresh_token").map(secret).transpose()?;
    let expiry = v
        .get("expires_in")
        .map(|e| {
            e.as_u64()
                .filter(|n| *n > 0 && *n <= 31536000)
                .and_then(|n| now().checked_add(n as i64))
                .ok_or(Error("token_invalid"))
        })
        .transpose()?;
    if v.get("issuer").is_some_and(|s| s != p.issuer.as_str())
        || v.get("iss").is_some_and(|s| s != p.issuer.as_str())
        || v.get("scope").is_some_and(|s| s != "read")
        || v.get("resource").is_some_and(|s| s != p.resource.as_str())
        || v.get("client_id")
            .is_some_and(|s| s != p.client_id.as_str())
    {
        return Err(Error("token_metadata_mismatch"));
    }
    Ok(Token {
        access,
        refresh,
        expiry,
        scope_echoed: v.get("scope").is_some(),
        granted_scope: v.get("scope").and_then(Value::as_str).map(str::to_owned),
    })
}

pub(super) async fn refresh(
    p: &config::Profile,
    client: &reqwest::Client,
    old: &Token,
    client_secret: Option<&str>,
) -> Result<Token> {
    let refresh = old.refresh.as_ref().ok_or(Error("refresh_unavailable"))?;
    let scope = p.scope();
    let mut form = vec![
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh.expose_secret()),
        ("client_id", &p.client_id),
        ("resource", &p.resource),
        ("scope", scope.as_str()),
    ];
    confidential(p, client_secret, &mut form)?;
    let (status, bytes) = super::token_io::post(p, client, &form).await?;
    super::token_io::refreshed(p, status, &bytes, old, client_secret)
}

fn confidential<'a>(
    p: &config::Profile,
    secret: Option<&'a str>,
    form: &mut Vec<(&'a str, &'a str)>,
) -> Result<()> {
    if p.confidential() {
        form.push(("client_secret", secret.ok_or(Error("client_unavailable"))?));
    } else if secret.is_some() {
        return Err(Error("profile_conflict"));
    }
    Ok(())
}
