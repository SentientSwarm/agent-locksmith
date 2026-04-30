use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use std::env;
use std::path::{Path, PathBuf};
use tracing::warn;

use crate::deprecation::{DeprecationDisposition, DeprecationRegistry, default_registry};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppConfig {
    pub listen: ListenConfig,
    pub inbound_auth: Option<InboundAuthConfig>,
    pub egress_proxy: Option<String>,
    pub logging: Option<LoggingConfig>,
    #[serde(default)]
    pub shutdown: ShutdownConfig,
    #[serde(default)]
    pub tools: Vec<ToolConfig>,
    /// Path to the operator credentials YAML file (M2). Required iff
    /// `listen.admin_socket` is set; main.rs validates the pairing at
    /// startup. Cleartext operator tokens are NOT here — only argon2 hashes
    /// and metadata.
    pub operator_credentials_path: Option<PathBuf>,
    /// SQLite database location (M2). Required iff `listen.admin_socket`
    /// is set; main.rs validates the pairing at startup.
    pub database: Option<DatabaseConfig>,
    /// Audit subsystem tuning (M3). Optional — daemon applies defaults
    /// (90-day retention, hourly sweep) when absent.
    pub audit: Option<AuditConfig>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DatabaseConfig {
    pub path: PathBuf,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct AuditConfig {
    /// Days of audit history to retain. Rows older than `now -
    /// retention_days` are deleted by the sweeper. Default 90 (Q-26 C).
    #[serde(default = "default_audit_retention_days")]
    pub retention_days: u32,
    /// Sweep cadence in seconds. Default 3600 (hourly).
    #[serde(default = "default_audit_sweep_interval_seconds")]
    pub sweep_interval_seconds: u64,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            retention_days: default_audit_retention_days(),
            sweep_interval_seconds: default_audit_sweep_interval_seconds(),
        }
    }
}

fn default_audit_retention_days() -> u32 {
    90
}

fn default_audit_sweep_interval_seconds() -> u64 {
    3600
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShutdownConfig {
    #[serde(default = "default_drain_window")]
    pub drain_window_seconds: u64,
}

impl Default for ShutdownConfig {
    fn default() -> Self {
        Self {
            drain_window_seconds: default_drain_window(),
        }
    }
}

fn default_drain_window() -> u64 {
    crate::shutdown::DEFAULT_DRAIN_WINDOW_SECS
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListenConfig {
    #[serde(default = "default_host")]
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
    /// Optional admin Unix-domain-socket listener (M2). When present the
    /// daemon binds the admin router (C-2) at this path with mode 0660.
    /// Absent ⇒ M0/M1 backward-compat behavior (TCP listener only).
    pub admin_socket: Option<AdminSocketConfig>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminSocketConfig {
    pub path: PathBuf,
}

fn default_host() -> String {
    "127.0.0.1".to_string()
}

fn default_port() -> u16 {
    9200
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InboundAuthConfig {
    pub mode: String,
    pub token: Option<SecretString>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoggingConfig {
    #[serde(default = "default_log_level")]
    pub level: String,
    pub file: Option<String>,
}

fn default_log_level() -> String {
    "info".to_string()
}

/// Per-tool egress routing (R-F13). Replaces M0's `cloud: bool`.
/// `direct`: route the upstream call without proxy intermediation
/// (LAN-bound services typically). `proxied`: route through the configured
/// `egress_proxy` HTTP CONNECT proxy (typically Pipelock for internet-bound
/// traffic, D-16).
#[derive(Debug, Deserialize, PartialEq, Eq, Clone, Copy)]
#[serde(rename_all = "lowercase")]
pub enum EgressMode {
    Direct,
    Proxied,
}

impl Default for EgressMode {
    fn default() -> Self {
        // Preserves M0 default (`cloud: false` ⇒ no proxy).
        Self::Direct
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolConfig {
    pub name: String,
    pub description: String,
    pub upstream: String,
    #[serde(default)]
    pub egress: EgressMode,
    pub auth: Option<ToolAuthConfig>,
    #[serde(default)]
    pub timeouts: ToolTimeouts,
    #[serde(default = "default_body_limit")]
    pub body_limit_bytes: u64,
}

/// Per-tool timeout configuration (R-F12).
/// `request_seconds` is the total request timeout (headers + body completion).
/// `idle_seconds` is the per-read inactivity timeout — useful for streaming
/// upstreams where the total duration is unbounded but inactivity should
/// terminate the connection.
#[derive(Debug, Deserialize, Clone, Copy)]
#[serde(deny_unknown_fields)]
pub struct ToolTimeouts {
    #[serde(default = "default_request_seconds")]
    pub request_seconds: u64,
    #[serde(default = "default_idle_seconds")]
    pub idle_seconds: u64,
}

impl Default for ToolTimeouts {
    fn default() -> Self {
        Self {
            request_seconds: default_request_seconds(),
            idle_seconds: default_idle_seconds(),
        }
    }
}

fn default_request_seconds() -> u64 {
    30
}

fn default_idle_seconds() -> u64 {
    60
}

fn default_body_limit() -> u64 {
    10 * 1024 * 1024
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolAuthConfig {
    pub header: String,
    pub value: SecretString,
}

impl AppConfig {
    /// Return tools that are active (have valid credentials or no auth required).
    /// Tools with an auth block but empty value are considered unconfigured.
    pub fn active_tools(&self) -> Vec<&ToolConfig> {
        self.tools
            .iter()
            .filter(|t| match &t.auth {
                Some(auth) => !auth.value.expose_secret().is_empty(),
                None => true,
            })
            .collect()
    }
}

/// Expand `${VAR_NAME}` patterns in a string using environment variables.
/// Missing variables expand to empty string.
///
/// NOTE (INF-23): textual pre-parse expansion is fragile when env values
/// contain YAML-significant characters (`:`, leading whitespace, `null`,
/// `true`, `false`, etc.). M2 introduces typed `SecretRef` parsing as the
/// recommended replacement. v2 keeps this behavior for backward compat
/// with M0 deployments.
pub fn expand_env_vars(input: &str) -> String {
    let mut result = input.to_string();
    while let Some(start) = result.find("${") {
        if let Some(end) = result[start..].find('}') {
            let var_name = &result[start + 2..start + end];
            let value = env::var(var_name).unwrap_or_default();
            result = format!(
                "{}{}{}",
                &result[..start],
                value,
                &result[start + end + 1..]
            );
        } else {
            break;
        }
    }
    result
}

/// Parse YAML text into `AppConfig` after env-var expansion and
/// deprecation interception.
///
/// The pipeline:
/// 1. Expand `${VAR}` patterns in the raw YAML text.
/// 2. Parse to an untyped `serde_yaml::Value` tree.
/// 3. Apply the deprecation registry (T1.5/T1.6/INF-24): rename / remove
///    legacy fields with a one-shot warning per field.
/// 4. Deserialize into typed `AppConfig` with `deny_unknown_fields`. Any
///    remaining unknown field is rejected with a structured error.
pub fn parse_config_str(raw: &str) -> Result<AppConfig, Box<dyn std::error::Error>> {
    let expanded = expand_env_vars(raw);
    let registry = default_registry();
    parse_with_registry(&expanded, &registry)
}

fn parse_with_registry(
    yaml: &str,
    registry: &DeprecationRegistry,
) -> Result<AppConfig, Box<dyn std::error::Error>> {
    let mut value: serde_yaml::Value = serde_yaml::from_str(yaml)?;
    apply_deprecations(&mut value, registry);
    let config: AppConfig = serde_yaml::from_value(value)?;
    Ok(config)
}

/// Walk the parsed YAML tree and apply registered deprecation rules
/// in-place. Each registered field encountered emits at most one warning
/// per registry lifetime via `registry.notice(path)`.
fn apply_deprecations(value: &mut serde_yaml::Value, registry: &DeprecationRegistry) {
    let serde_yaml::Value::Mapping(top) = value else {
        return;
    };

    // Top-level: telemetry (removed)
    let telemetry_key = serde_yaml::Value::String("telemetry".to_string());
    if top.contains_key(&telemetry_key) {
        emit_deprecation(registry, "telemetry");
        top.remove(&telemetry_key);
    }

    // tools[]: cloud → egress, timeout_seconds → timeouts.request_seconds.
    let tools_key = serde_yaml::Value::String("tools".to_string());
    if let Some(serde_yaml::Value::Sequence(tools)) = top.get_mut(&tools_key) {
        for tool in tools {
            let serde_yaml::Value::Mapping(tool_map) = tool else {
                continue;
            };
            translate_cloud(tool_map, registry);
            translate_timeout_seconds(tool_map, registry);
        }
    }
}

fn translate_cloud(tool_map: &mut serde_yaml::Mapping, registry: &DeprecationRegistry) {
    let cloud_key = serde_yaml::Value::String("cloud".to_string());
    let egress_key = serde_yaml::Value::String("egress".to_string());
    if let Some(cloud_val) = tool_map.remove(&cloud_key) {
        emit_deprecation(registry, "tools[].cloud");
        // Explicit `egress` wins if both are present.
        if !tool_map.contains_key(&egress_key) {
            let new_egress = match cloud_val {
                serde_yaml::Value::Bool(true) => "proxied",
                serde_yaml::Value::Bool(false) => "direct",
                _ => "direct",
            };
            tool_map.insert(
                egress_key,
                serde_yaml::Value::String(new_egress.to_string()),
            );
        }
    }
}

fn translate_timeout_seconds(tool_map: &mut serde_yaml::Mapping, registry: &DeprecationRegistry) {
    let legacy_key = serde_yaml::Value::String("timeout_seconds".to_string());
    let timeouts_key = serde_yaml::Value::String("timeouts".to_string());
    let request_seconds_key = serde_yaml::Value::String("request_seconds".to_string());
    let Some(legacy_val) = tool_map.remove(&legacy_key) else {
        return;
    };
    emit_deprecation(registry, "tools[].timeout_seconds");
    // Explicit `timeouts.request_seconds` wins if already set; do nothing
    // beyond the warning + drop in that case.
    if let Some(serde_yaml::Value::Mapping(existing_timeouts)) = tool_map.get(&timeouts_key)
        && existing_timeouts.contains_key(&request_seconds_key)
    {
        return;
    }
    // Insert `timeouts.request_seconds: <legacy_val>`, preserving any
    // partial timeouts mapping the operator may have provided.
    let timeouts_entry = tool_map
        .entry(timeouts_key)
        .or_insert_with(|| serde_yaml::Value::Mapping(serde_yaml::Mapping::new()));
    if let serde_yaml::Value::Mapping(existing) = timeouts_entry {
        existing.insert(request_seconds_key, legacy_val);
    }
}

fn emit_deprecation(registry: &DeprecationRegistry, field_path: &str) {
    if !registry.notice(field_path) {
        return;
    }
    let entry = match registry.lookup(field_path) {
        Some(e) => e,
        None => return,
    };
    match &entry.disposition {
        DeprecationDisposition::Renamed { new_name } => warn!(
            field = field_path,
            replacement = *new_name,
            since_version = entry.since_version,
            removal_target = entry.removal_target.unwrap_or(""),
            "configuration field renamed; replace with the documented field"
        ),
        DeprecationDisposition::Deprecated => warn!(
            field = field_path,
            since_version = entry.since_version,
            removal_target = entry.removal_target.unwrap_or(""),
            "configuration field deprecated; please migrate"
        ),
        DeprecationDisposition::Removed => warn!(
            field = field_path,
            since_version = entry.since_version,
            "configuration field removed; value is ignored"
        ),
    }
}

/// Load config from YAML file. Convenience wrapper over `parse_config_str`
/// that reads the file from disk.
pub fn load_config(path: &Path) -> Result<AppConfig, Box<dyn std::error::Error>> {
    let raw = std::fs::read_to_string(path)?;
    parse_config_str(&raw)
}
