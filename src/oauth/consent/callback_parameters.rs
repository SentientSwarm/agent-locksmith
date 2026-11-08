use super::*;
use axum::extract::Request;
use std::collections::BTreeMap;

type Parameters = (String, Option<String>, Option<String>);

pub(super) fn parameters(rt: &Runtime, req: &Request) -> Result<Parameters> {
    target(rt, req)?;
    let mut fields = fields(req.uri().query().ok_or(Error("callback_refused"))?)?;
    let state = fields
        .remove("state")
        .filter(|s| s.len() == 43)
        .ok_or(Error("callback_refused"))?;
    let issuer = fields.remove("iss");
    if issuer.as_ref().is_some_and(|s| s.is_empty())
        || (issuer.is_none() && req.uri().path() == callback_route::GENERIC)
    {
        return Err(Error("callback_refused"));
    }
    let code = fields.remove("code");
    let error = fields.remove("error");
    if code.is_some() == error.is_some()
        || code.as_ref().is_some_and(|s| s.is_empty())
        || error.as_ref().is_some_and(|s| s.is_empty())
    {
        return Err(Error("callback_refused"));
    }
    Ok((state, issuer, code))
}

fn target(rt: &Runtime, req: &Request) -> Result<()> {
    if req.method() != axum::http::Method::GET
        || !rt
            .config
            .profiles
            .iter()
            .any(|p| p.callback_uri().is_ok_and(|u| u.path() == req.uri().path()))
        || req.uri().scheme().is_some()
        || req.uri().authority().is_some()
        || req.uri().to_string().len() > 8192
        || req.headers().get_all("host").iter().count() != 1
        || !rt.config.profiles.iter().any(|p| {
            p.callback_authority().ok().as_deref()
                == req.headers().get("host").and_then(|v| v.to_str().ok())
        })
        || req
            .headers()
            .keys()
            .any(|k| k.as_str() == "forwarded" || k.as_str().starts_with("x-forwarded-"))
    {
        return Err(Error("callback_refused"));
    }
    Ok(())
}

fn fields(query: &str) -> Result<BTreeMap<String, String>> {
    escapes(query)?;
    let url = reqwest::Url::parse(&format!("https://127.0.0.1/?{query}"))
        .map_err(|_| Error("callback_refused"))?;
    let mut fields = BTreeMap::new();
    for (index, (k, v)) in url.query_pairs().enumerate() {
        if index >= 16
            || k.len() > 128
            || v.len() > 4096
            || !k.is_ascii()
            || !v.is_ascii()
            || v.bytes().any(|b| b < 0x20 || b == 0x7f)
            || fields.insert(k.to_string(), v.to_string()).is_some()
        {
            return Err(Error("callback_refused"));
        }
    }
    Ok(fields)
}

fn escapes(query: &str) -> Result<()> {
    for (i, b) in query.bytes().enumerate() {
        if b == b'%'
            && (query
                .as_bytes()
                .get(i + 1)
                .is_none_or(|b| !b.is_ascii_hexdigit())
                || query
                    .as_bytes()
                    .get(i + 2)
                    .is_none_or(|b| !b.is_ascii_hexdigit()))
        {
            return Err(Error("callback_refused"));
        }
    }
    Ok(())
}
