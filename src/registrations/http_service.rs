//! Opt-in public HTTP descriptions; never an authority or execution policy.
mod validation;

use super::RegistrationError;
use serde::{Deserialize, Deserializer, Serialize, de::IntoDeserializer};
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HttpService {
    pub version: u32,
    #[serde(deserialize_with = "string_enum")]
    pub mode: Mode,
    pub operations: Vec<Operation>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    RequestResponse,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Operation {
    pub id: String,
    pub summary: String,
    #[serde(deserialize_with = "string_enum")]
    pub method: Method,
    pub path: String,
    #[serde(default)]
    pub query: Vec<Field>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_body: Option<RequestBody>,
    pub response: Response,
    #[serde(default)]
    pub errors: Vec<ServiceError>,
    pub example: Example,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Method {
    Get,
    Post,
    Put,
    Patch,
    Delete,
    Head,
    Options,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Field {
    pub name: String,
    #[serde(rename = "type", deserialize_with = "string_enum")]
    pub field_type: FieldType,
    pub required: bool,
    pub description: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldType {
    String,
    Integer,
    Number,
    Boolean,
    Object,
    Array,
}

#[derive(Debug, Deserialize, Serialize)]
pub enum ContentType {
    #[serde(rename = "application/json")]
    Json,
    #[serde(rename = "text/plain")]
    Text,
}

#[derive(Debug, Deserialize, Serialize)]
pub enum JsonContentType {
    #[serde(rename = "application/json")]
    Json,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RequestBody {
    #[serde(deserialize_with = "string_enum")]
    pub content_type: JsonContentType,
    pub required: bool,
    pub fields: Vec<Field>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Response {
    pub status: u16,
    #[serde(deserialize_with = "string_enum")]
    pub content_type: ContentType,
    #[serde(default)]
    pub fields: Vec<Field>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceError {
    pub status: u16,
    pub description: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Example {
    #[serde(default)]
    pub query: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<Value>,
    pub response: Value,
}

// Serde also accepts {"Variant":null} for unit enums; the wire contract is a string.
fn string_enum<'de, D: Deserializer<'de>, T: Deserialize<'de>>(d: D) -> Result<T, D::Error> {
    T::deserialize(String::deserialize(d)?.into_deserializer())
}

/// Legacy metadata of any JSON shape remains private and compatible.
/// A present descriptor is validated even when null or otherwise malformed.
pub fn from_metadata(metadata: &Value) -> Result<Option<HttpService>, RegistrationError> {
    let Some(raw) = metadata.as_object().and_then(|m| m.get("http_service")) else {
        return Ok(None);
    };
    if raw.to_string().len() > 64 * 1024 {
        return Err(RegistrationError::InvalidHttpService);
    }
    let service: HttpService =
        serde_json::from_value(raw.clone()).map_err(|_| RegistrationError::InvalidHttpService)?;
    if !validation::valid(&service) {
        return Err(RegistrationError::InvalidHttpService);
    }
    Ok(Some(service))
}
