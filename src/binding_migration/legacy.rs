use super::{
    Error,
    types::{Legacy, LegacyShape, Registration},
};
use crate::registrations::AuthSpec;
use serde_yaml::Value;
use std::path::Path;

pub(super) fn inventory(path: Option<&Path>) -> Result<Vec<Legacy>, Error> {
    let Some(path) = path else {
        return Ok(vec![Legacy {
            name: "config.tools".into(),
            shape: LegacyShape::NotInventoried,
            reference: None,
            reason: "not_inventoried_supply_legacy_config_or_review_identityless_paths_separately"
                .into(),
        }]);
    };
    // Parse metadata without AppConfig's environment expansion/resolution.
    let bytes = std::fs::read(path).map_err(|_| Error::Invalid)?;
    let yaml: serde_yaml::Value = serde_yaml::from_slice(&bytes).map_err(|_| Error::Invalid)?;
    let Some(tools) = yaml.get("tools") else {
        return Ok(Vec::new());
    };
    let tools = tools.as_sequence().ok_or(Error::Invalid)?;
    let mut rows = tools.iter().map(tool).collect::<Result<Vec<_>, _>>()?;
    rows.sort_by(|a, b| a.name.cmp(&b.name).then(a.reason.cmp(&b.reason)));
    Ok(rows)
}
fn tool(value: &serde_yaml::Value) -> Result<Legacy, Error> {
    let name = value
        .get("name")
        .and_then(|v| v.as_str())
        .ok_or(Error::Invalid)?;
    let (shape, reference) = source(value.get("auth"));
    let file = shape == LegacyShape::File;
    Ok(Legacy {
        name: name.into(),
        shape,
        reference,
        reason: if file {
            "unsupported_file_source_owner_mapping_and_registered_agent_required"
        } else {
            "identityless_legacy_path_register_authenticate_agent_and_select_source"
        }
        .into(),
    })
}
fn source(auth: Option<&Value>) -> (LegacyShape, Option<AuthSpec>) {
    let Some(auth) = auth.filter(|v| !v.is_null()) else {
        return (LegacyShape::None, Some(AuthSpec::None));
    };
    let Some(value) = auth.get("value") else {
        return (LegacyShape::Unsupported, None);
    };
    if let Some(raw) = value.as_str() {
        let reference = crate::registrations::legacy_bootstrap::extract_single_env_var(raw)
            .and_then(|name| header_reference(auth, &name));
        return (LegacyShape::String, reference);
    }
    let Some(map) = value.as_mapping().filter(|m| m.len() == 1) else {
        return (LegacyShape::Unsupported, None);
    };
    if map.contains_key(Value::from("from_file_sealed")) {
        return (LegacyShape::File, None);
    }
    let Some(env) = value.get("from_env") else {
        return (LegacyShape::Unsupported, None);
    };
    environment(auth, env)
}
fn environment(auth: &Value, env: &Value) -> (LegacyShape, Option<AuthSpec>) {
    let shape = if env
        .get("prefix")
        .is_none_or(|p| p.is_null() || p.as_str() == Some(""))
    {
        LegacyShape::Env
    } else {
        LegacyShape::EnvTransformed
    };
    let reference = env
        .get("var")
        .and_then(Value::as_str)
        .and_then(|name| header_reference(auth, name));
    (shape, reference)
}

pub(super) fn mapping_reason(rows: &[Legacy], registration: &Registration) -> Option<&'static str> {
    let mut matches = rows
        .iter()
        .filter(|r| r.name == registration.name && r.shape != LegacyShape::NotInventoried);
    let row = matches.next()?;
    if matches.next().is_some() {
        return Some("ambiguous_legacy_source_owner_mapping_required");
    }
    if !matches!(row.shape, LegacyShape::Env | LegacyShape::None) {
        return Some("unsupported_legacy_wire_shape_owner_mapping_required");
    }
    if !equivalent(row.reference.as_ref(), registration.auth.as_ref()) {
        return Some("legacy_source_reference_mismatch_owner_mapping_required");
    }
    None
}
fn equivalent(legacy: Option<&AuthSpec>, current: Option<&AuthSpec>) -> bool {
    match (legacy, current) {
        (Some(AuthSpec::None), Some(AuthSpec::None)) => true,
        (
            Some(AuthSpec::Header {
                header: a,
                env_var: x,
            }),
            Some(AuthSpec::Header {
                header: b,
                env_var: y,
            }),
        ) => a.eq_ignore_ascii_case(b) && x == y,
        _ => false,
    }
}

fn header_reference(auth: &Value, name: &str) -> Option<AuthSpec> {
    auth.get("header")
        .and_then(Value::as_str)
        .map(|header| AuthSpec::Header {
            header: header.into(),
            env_var: name.into(),
        })
}
