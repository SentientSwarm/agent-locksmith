//! The `inspection:` config block and its compilation.
//!
//! ```yaml
//! inspection:
//!   routes:
//!     - route: search            # a registration or config tool name
//!       request:
//!         scanners: [dlp]
//!         on_hit: block          # pass | flag | redact | block
//!         on_error: fail_closed  # fail_open | fail_closed
//!         max_scan_bytes: 1048576
//!       response:
//!         scanners: [injection]
//! ```
//!
//! Defaults: requests `block` / `fail_closed`; responses `flag` /
//! `fail_open` (`fail_closed` when `on_hit` redacts or blocks); 1 MiB
//! scan limit. A policy whose only scanners are
//! `injection` or sidecars defaults to `flag` in both directions. Unknown
//! scanners and duplicate routes fail config load.
//!
//! ```yaml
//! inspection:
//!   sidecars:                    # AGENT-254: scanners behind a Unix socket
//!     - name: promptguard        # used as scanner `sidecar:promptguard`
//!       socket: /run/locksmith-inspector/inspector.sock
//!       timeout_ms: 1000         # default 1000
//! ```

use super::{DirectionPolicy, Inspection, OnError, RoutePolicy, Scanner, Verdict};
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;

const DEFAULT_MAX_SCAN_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InspectionConfig {
    #[serde(default)]
    pub routes: Vec<RouteInspectionConfig>,
    #[serde(default)]
    pub sidecars: Vec<SidecarConfig>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SidecarConfig {
    pub name: String,
    pub socket: std::path::PathBuf,
    pub timeout_ms: Option<u64>,
}

const DEFAULT_SIDECAR_TIMEOUT_MS: u64 = 1000;

type Sidecars = HashMap<String, Arc<dyn Scanner>>;

fn sidecars(cfg: Option<&InspectionConfig>) -> Result<Sidecars, String> {
    let mut out = Sidecars::new();
    for s in cfg.map(|c| c.sidecars.as_slice()).unwrap_or_default() {
        let valid = !s.name.is_empty()
            && s.name
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_');
        if !valid {
            return Err(format!(
                "inspection sidecar name `{}` must be [a-z0-9_-]+",
                s.name
            ));
        }
        if !s.socket.is_absolute() {
            return Err(format!(
                "inspection sidecar `{}` socket must be an absolute path",
                s.name
            ));
        }
        let timeout = s.timeout_ms.unwrap_or(DEFAULT_SIDECAR_TIMEOUT_MS);
        if timeout == 0 {
            return Err(format!(
                "inspection sidecar `{}` timeout_ms must be at least 1",
                s.name
            ));
        }
        let scanner = super::sidecar::Sidecar::new(
            &s.name,
            s.socket.clone(),
            std::time::Duration::from_millis(timeout),
        );
        if out.insert(s.name.clone(), Arc::new(scanner)).is_some() {
            return Err(format!("inspection sidecar `{}` is listed twice", s.name));
        }
    }
    Ok(out)
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteInspectionConfig {
    pub route: String,
    pub request: Option<DirectionConfig>,
    pub response: Option<DirectionConfig>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectionConfig {
    pub scanners: Vec<String>,
    pub on_hit: Option<Verdict>,
    pub on_error: Option<OnError>,
    pub max_scan_bytes: Option<usize>,
}

/// Compile the config into per-route policies.
pub fn compile(cfg: Option<&InspectionConfig>) -> Result<Inspection, String> {
    let sidecars = sidecars(cfg)?;
    let mut routes = HashMap::new();
    for r in cfg.map(|c| c.routes.as_slice()).unwrap_or_default() {
        let policy = RoutePolicy {
            request: direction(
                r.request.as_ref(),
                Verdict::Block,
                OnError::FailClosed,
                &sidecars,
            )
            .map_err(|e| format!("inspection route `{}` request: {e}", r.route))?,
            response: direction(
                r.response.as_ref(),
                Verdict::Flag,
                OnError::FailOpen,
                &sidecars,
            )
            .map_err(|e| format!("inspection route `{}` response: {e}", r.route))?,
        };
        if routes.insert(r.route.clone(), policy).is_some() {
            return Err(format!("inspection route `{}` is listed twice", r.route));
        }
    }
    Ok(Inspection { routes })
}

fn direction(
    cfg: Option<&DirectionConfig>,
    on_hit: Verdict,
    on_error: OnError,
    sidecars: &Sidecars,
) -> Result<Option<DirectionPolicy>, String> {
    let Some(cfg) = cfg else { return Ok(None) };
    if cfg.scanners.is_empty() {
        return Err("names no scanners".into());
    }
    let on_hit = cfg.on_hit.unwrap_or(if advisory_only(&cfg.scanners) {
        Verdict::Flag
    } else {
        on_hit
    });
    // AGENT-270: a policy that redacts or blocks must not be bypassed by a
    // body it can't read (a compressed reply, say), so it fails closed
    // unless the operator says otherwise.
    let on_error = if on_hit >= Verdict::Redact {
        OnError::FailClosed
    } else {
        on_error
    };
    Ok(Some(DirectionPolicy {
        scanners: cfg
            .scanners
            .iter()
            .map(|id| scanner(id, sidecars))
            .collect::<Result<_, _>>()?,
        on_hit,
        on_error: cfg.on_error.unwrap_or(on_error),
        max_scan_bytes: cfg.max_scan_bytes.unwrap_or(DEFAULT_MAX_SCAN_BYTES),
    }))
}

/// Phrase matching and classifier scores are too coarse to block on
/// unasked: a policy of only `injection` or sidecars defaults to `flag`
/// in either direction.
fn advisory_only(scanners: &[String]) -> bool {
    scanners
        .iter()
        .all(|s| s == "injection" || s.starts_with("sidecar:"))
}

fn scanner(id: &str, sidecars: &Sidecars) -> Result<Arc<dyn Scanner>, String> {
    if let Some(name) = id.strip_prefix("sidecar:") {
        return sidecars
            .get(name)
            .cloned()
            .ok_or_else(|| format!("scanner `{id}` names no configured sidecar"));
    }
    if id == "injection" {
        return Ok(Arc::new(super::injection::Injection));
    }
    if id == "dlp" {
        return Ok(Arc::new(super::dlp::Dlp));
    }
    if let Some(needle) = id.strip_prefix("literal:") {
        return Ok(Arc::new(super::literal::Literal::new(needle)?));
    }
    Err(format!("unknown scanner `{id}`"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The compiled (on_hit, on_error) for one route's request or response.
    fn compiled(direction: &str, policy: &str) -> (Verdict, OnError) {
        let yaml = format!("routes:\n  - route: r\n    {direction}:\n{policy}");
        let cfg: InspectionConfig = serde_yaml::from_str(&yaml).unwrap();
        let inspection = compile(Some(&cfg)).unwrap();
        let route = inspection.policy("r").unwrap();
        let p = match direction {
            "request" => route.request.as_ref(),
            _ => route.response.as_ref(),
        }
        .unwrap();
        (p.on_hit, p.on_error)
    }

    #[test]
    fn response_on_error_follows_on_hit() {
        use OnError::*;
        use Verdict::*;
        let cases = [
            ("      scanners: [dlp]\n", (Flag, FailOpen)),
            (
                "      scanners: [dlp]\n      on_hit: pass\n",
                (Pass, FailOpen),
            ),
            (
                "      scanners: [dlp]\n      on_hit: redact\n",
                (Redact, FailClosed),
            ),
            (
                "      scanners: [dlp]\n      on_hit: block\n",
                (Block, FailClosed),
            ),
            (
                "      scanners: [injection]\n      on_hit: block\n",
                (Block, FailClosed),
            ),
            (
                "      scanners: [dlp]\n      on_hit: redact\n      on_error: fail_open\n",
                (Redact, FailOpen),
            ),
        ];
        for (policy, want) in cases {
            assert_eq!(compiled("response", policy), want, "{policy}");
        }
    }

    #[test]
    fn request_defaults_are_unchanged() {
        use OnError::*;
        use Verdict::*;
        assert_eq!(
            compiled("request", "      scanners: [dlp]\n"),
            (Block, FailClosed)
        );
        assert_eq!(
            compiled("request", "      scanners: [injection]\n"),
            (Flag, FailClosed)
        );
    }
}
