//! Phase E.4 — shared CLI dispatch for the three registration kinds.
//!
//! `locksmith {tool, model, infra}` subcommands all reach the same admin
//! endpoints (`/admin/operator/{tools,models,infra}/<name>`); the only
//! per-kind variation is the URL segment and a few validation rules
//! (handled server-side). This module factors the option parser + HTTP
//! dispatch out of the three thin per-kind modules.

use clap::Args;
use serde_json::{Value, json};

use crate::client::{Auth, CliClient, CliError};
use crate::output::{Format, print};

/// Three registration kinds. Mirrors `agent_locksmith::registrations::Kind`
/// but lives in the CLI so we don't drag the lib's serde derives into the
/// binary. The URL segment matches the admin endpoint path.
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)] // variants are constructed in tool.rs / model.rs / infra.rs
// (cross-module construction trips dead-code analysis on
// bin targets in some workspace layouts).
pub enum CliKind {
    Tool,
    Model,
    Infra,
}

impl CliKind {
    pub fn url_segment(self) -> &'static str {
        match self {
            CliKind::Tool => "tools",
            CliKind::Model => "models",
            CliKind::Infra => "infra",
        }
    }
}

/// Shared `--upstream / --auth / --metadata / ...` option set. Used
/// verbatim by `tool put`, `model put`, `infra put`.
#[derive(Args, Debug)]
pub struct PutOpts {
    /// Upstream URL the registration proxies to. Required.
    #[arg(long)]
    pub upstream: String,

    /// Auth shape. Accepted forms:
    ///   `none`                         (kind=tool only — explicit authless;
    ///                                    field absent on kind=tool → 400)
    ///   `header:<HEADER>=<ENV_VAR>`    inject `<HEADER>: <env-var-value>`
    ///   `bearer=<ENV_VAR>`             inject `Authorization: Bearer <env-var-value>`
    ///
    /// kind=model rejects `none`. kind=infra accepts any (omit for AuthSpec::None).
    #[arg(long)]
    pub auth: Option<String>,

    /// Egress: `direct` or `proxied`. Defaults to `proxied` server-side.
    #[arg(long)]
    pub egress: Option<String>,

    /// Per-request timeout in seconds. Defaults server-side.
    #[arg(long = "timeout-request")]
    pub timeout_request: Option<u64>,

    /// Per-read idle timeout in seconds. Defaults server-side.
    #[arg(long = "timeout-idle")]
    pub timeout_idle: Option<u64>,

    /// Maximum response body size accepted from the upstream, in bytes.
    /// Defaults server-side (10 MiB).
    #[arg(long = "body-limit")]
    pub body_limit: Option<u64>,

    /// Per-kind metadata. Repeatable: `--metadata modality=text --metadata
    /// provider=anthropic`. The CLI sends the merged JSON object to the
    /// server; per-kind required-field validation runs server-side.
    #[arg(long, value_parser = parse_metadata_kv)]
    pub metadata: Vec<(String, String)>,

    /// Optional description. Empty by default.
    #[arg(long)]
    pub description: Option<String>,
}

fn parse_metadata_kv(s: &str) -> Result<(String, String), String> {
    let (k, v) = s
        .split_once('=')
        .ok_or_else(|| format!("metadata must be key=value, got: {s}"))?;
    if k.is_empty() {
        return Err(format!("metadata key empty in: {s}"));
    }
    Ok((k.to_string(), v.to_string()))
}

/// Parse an `--auth <spec>` string into the JSON shape expected by the
/// admin endpoint's PUT body. Returns `None` when the operator omitted
/// `--auth` entirely; the server then applies the per-kind defaults
/// (kind=infra → AuthSpec::None; kind=tool → 400 auth_required;
/// kind=model → 400 auth_required).
pub fn parse_auth_spec(spec: Option<&str>) -> Result<Option<Value>, CliError> {
    let Some(s) = spec else { return Ok(None) };
    let s = s.trim();
    if s == "none" {
        return Ok(Some(json!({ "kind": "none" })));
    }
    if let Some(rest) = s.strip_prefix("bearer=") {
        if rest.is_empty() {
            return Err(CliError::Usage(format!(
                "--auth bearer=<ENV_VAR>: missing env var name in: {s}"
            )));
        }
        return Ok(Some(json!({ "kind": "bearer", "env_var": rest })));
    }
    if let Some(rest) = s.strip_prefix("header:") {
        let (header, env_var) = rest.split_once('=').ok_or_else(|| {
            CliError::Usage(format!(
                "--auth header:<NAME>=<ENV_VAR>: missing '=' in: {s}"
            ))
        })?;
        if header.is_empty() || env_var.is_empty() {
            return Err(CliError::Usage(format!(
                "--auth header:<NAME>=<ENV_VAR>: name and env-var must be non-empty in: {s}"
            )));
        }
        return Ok(Some(json!({
            "kind": "header",
            "header": header,
            "env_var": env_var
        })));
    }
    Err(CliError::Usage(format!(
        "--auth must be one of: none | bearer=<ENV_VAR> | header:<NAME>=<ENV_VAR>; got: {s}"
    )))
}

// ─── Dispatch helpers ──────────────────────────────────────────────────────

pub async fn do_list(client: &CliClient, format: Format, kind: CliKind) -> Result<(), CliError> {
    let token = CliClient::op_token()?;
    let path = format!("/admin/operator/{}", kind.url_segment());
    let resp: Value = client
        .json("GET", &path, Auth::Operator(&token), None)
        .await?;
    print(
        &resp[format!("{}s", kind.url_segment().trim_end_matches('s'))],
        format,
    );
    Ok(())
}

pub async fn do_get(
    client: &CliClient,
    format: Format,
    kind: CliKind,
    name: &str,
) -> Result<(), CliError> {
    let token = CliClient::op_token()?;
    let path = format!("/admin/operator/{}/{}", kind.url_segment(), name);
    let resp: Value = client
        .json("GET", &path, Auth::Operator(&token), None)
        .await?;
    print(&resp, format);
    Ok(())
}

pub async fn do_put(
    client: &CliClient,
    format: Format,
    kind: CliKind,
    name: &str,
    opts: PutOpts,
) -> Result<(), CliError> {
    let token = CliClient::op_token()?;
    let auth = parse_auth_spec(opts.auth.as_deref())?;

    // Build request body from PutOpts. Fields the operator didn't set
    // are omitted so the server applies its defaults (egress=proxied,
    // body_limit=10MiB, etc.).
    let mut body = serde_json::Map::new();
    body.insert("upstream".into(), json!(opts.upstream));
    if let Some(d) = opts.description {
        body.insert("description".into(), json!(d));
    }
    if let Some(a) = auth {
        body.insert("auth".into(), a);
    }
    if let Some(e) = opts.egress {
        body.insert("egress".into(), json!(e));
    }
    if opts.timeout_request.is_some() || opts.timeout_idle.is_some() {
        let mut timeouts = serde_json::Map::new();
        if let Some(r) = opts.timeout_request {
            timeouts.insert("request_seconds".into(), json!(r));
        }
        if let Some(i) = opts.timeout_idle {
            timeouts.insert("idle_seconds".into(), json!(i));
        }
        body.insert("timeouts".into(), Value::Object(timeouts));
    }
    if let Some(bl) = opts.body_limit {
        body.insert("body_limit_bytes".into(), json!(bl));
    }
    if !opts.metadata.is_empty() {
        let mut md = serde_json::Map::new();
        for (k, v) in opts.metadata {
            md.insert(k, json!(v));
        }
        body.insert("metadata".into(), Value::Object(md));
    }

    let path = format!("/admin/operator/{}/{}", kind.url_segment(), name);
    let body_value = Value::Object(body);
    let resp: Value = client
        .json("PUT", &path, Auth::Operator(&token), Some(&body_value))
        .await?;
    print(&resp, format);
    Ok(())
}

pub async fn do_delete(
    client: &CliClient,
    _format: Format,
    kind: CliKind,
    name: &str,
) -> Result<(), CliError> {
    let token = CliClient::op_token()?;
    let path = format!("/admin/operator/{}/{}", kind.url_segment(), name);
    client
        .json::<Value>("DELETE", &path, Auth::Operator(&token), None)
        .await?;
    Ok(())
}

pub async fn do_enable(
    client: &CliClient,
    _format: Format,
    kind: CliKind,
    name: &str,
) -> Result<(), CliError> {
    let token = CliClient::op_token()?;
    let path = format!("/admin/operator/{}/{}/enable", kind.url_segment(), name);
    client
        .json::<Value>("POST", &path, Auth::Operator(&token), None)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ─── TS-143 / TS-144: --auth parser ────────────────────────────────────

    #[test]
    fn ts143_parse_auth_none() {
        let v = parse_auth_spec(Some("none")).unwrap().unwrap();
        assert_eq!(v, json!({ "kind": "none" }));
    }

    #[test]
    fn ts143_parse_auth_bearer() {
        let v = parse_auth_spec(Some("bearer=OPENAI_API_KEY"))
            .unwrap()
            .unwrap();
        assert_eq!(v, json!({ "kind": "bearer", "env_var": "OPENAI_API_KEY" }));
    }

    #[test]
    fn ts143_parse_auth_header() {
        let v = parse_auth_spec(Some("header:x-api-key=ANTHROPIC_API_KEY"))
            .unwrap()
            .unwrap();
        assert_eq!(
            v,
            json!({
                "kind": "header",
                "header": "x-api-key",
                "env_var": "ANTHROPIC_API_KEY"
            })
        );
    }

    #[test]
    fn ts143_parse_auth_omitted_returns_none() {
        let v = parse_auth_spec(None).unwrap();
        assert!(
            v.is_none(),
            "omitted --auth maps to None (server applies kind defaults)"
        );
    }

    #[test]
    fn ts143_parse_auth_rejects_garbage() {
        assert!(parse_auth_spec(Some("oauth=foo")).is_err());
        assert!(parse_auth_spec(Some("bearer=")).is_err());
        assert!(parse_auth_spec(Some("header:=KEY")).is_err());
        assert!(parse_auth_spec(Some("header:NAME=")).is_err());
        assert!(parse_auth_spec(Some("")).is_err());
    }

    #[test]
    fn ts144_parse_metadata_kv() {
        let (k, v) = parse_metadata_kv("modality=text").unwrap();
        assert_eq!(k, "modality");
        assert_eq!(v, "text");

        // Empty value allowed (operator can clear a default).
        let (k, v) = parse_metadata_kv("flag=").unwrap();
        assert_eq!(k, "flag");
        assert_eq!(v, "");

        // Empty key rejected.
        assert!(parse_metadata_kv("=value").is_err());
        assert!(parse_metadata_kv("no-equals").is_err());
    }

    #[test]
    fn ts140_url_segment_per_kind() {
        // Sanity: dispatch URL segment matches admin endpoint mount points.
        assert_eq!(CliKind::Tool.url_segment(), "tools");
        assert_eq!(CliKind::Model.url_segment(), "models");
        assert_eq!(CliKind::Infra.url_segment(), "infra");
    }
}
