use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use std::env;
use std::path::Path;

#[derive(Debug, Deserialize)]
pub struct AppConfig {
    pub listen: ListenConfig,
    pub inbound_auth: Option<InboundAuthConfig>,
    pub egress_proxy: Option<String>,
    pub telemetry: Option<TelemetryConfig>,
    pub logging: Option<LoggingConfig>,
    #[serde(default)]
    pub tools: Vec<ToolConfig>,
}

#[derive(Debug, Deserialize)]
pub struct ListenConfig {
    #[serde(default = "default_host")]
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
}

fn default_host() -> String {
    "127.0.0.1".to_string()
}

fn default_port() -> u16 {
    9200
}

#[derive(Debug, Deserialize)]
pub struct InboundAuthConfig {
    pub mode: String,
    pub token: Option<SecretString>,
}

#[derive(Debug, Deserialize)]
pub struct TelemetryConfig {
    #[serde(default)]
    pub enabled: bool,
    pub otlp_endpoint: Option<String>,
    pub service_name: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct LoggingConfig {
    #[serde(default = "default_log_level")]
    pub level: String,
    pub file: Option<String>,
}

fn default_log_level() -> String {
    "info".to_string()
}

#[derive(Debug, Deserialize)]
pub struct ToolConfig {
    pub name: String,
    pub description: String,
    pub upstream: String,
    #[serde(default)]
    pub cloud: bool,
    pub auth: Option<ToolAuthConfig>,
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u64,
}

fn default_timeout() -> u64 {
    30
}

#[derive(Debug, Deserialize)]
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

/// Load config from YAML file, expanding `${VAR}` patterns in the raw YAML
/// before parsing. This ensures SecretString fields get the resolved values.
pub fn load_config(path: &Path) -> Result<AppConfig, Box<dyn std::error::Error>> {
    let raw = std::fs::read_to_string(path)?;
    let expanded = expand_env_vars(&raw);
    let config: AppConfig = serde_yaml::from_str(&expanded)?;
    Ok(config)
}
