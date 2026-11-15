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
//! `fail_open`; 1 MiB scan limit. Unknown scanners and duplicate routes
//! fail config load.

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
    let mut routes = HashMap::new();
    for r in cfg.map(|c| c.routes.as_slice()).unwrap_or_default() {
        let policy = RoutePolicy {
            request: direction(r.request.as_ref(), Verdict::Block, OnError::FailClosed)
                .map_err(|e| format!("inspection route `{}` request: {e}", r.route))?,
            response: direction(r.response.as_ref(), Verdict::Flag, OnError::FailOpen)
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
) -> Result<Option<DirectionPolicy>, String> {
    let Some(cfg) = cfg else { return Ok(None) };
    if cfg.scanners.is_empty() {
        return Err("names no scanners".into());
    }
    Ok(Some(DirectionPolicy {
        scanners: cfg
            .scanners
            .iter()
            .map(|id| scanner(id))
            .collect::<Result<_, _>>()?,
        on_hit: cfg.on_hit.unwrap_or(on_hit),
        on_error: cfg.on_error.unwrap_or(on_error),
        max_scan_bytes: cfg.max_scan_bytes.unwrap_or(DEFAULT_MAX_SCAN_BYTES),
    }))
}

fn scanner(id: &str) -> Result<Arc<dyn Scanner>, String> {
    if let Some(needle) = id.strip_prefix("literal:") {
        return Ok(Arc::new(super::literal::Literal::new(needle)?));
    }
    Err(format!("unknown scanner `{id}`"))
}
