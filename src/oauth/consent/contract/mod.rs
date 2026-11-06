//! Closed, declarative wire adapters; custody and authority remain in consent.
mod identity;
pub(super) mod publication;
mod scope;
mod slack;
mod subject;
mod token;
mod validate;

use serde::{Deserialize, Serialize};
pub use subject::Subject;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Contract {
    pub version: u8,
    pub grant: String,
    pub registration: String,
    pub client_auth: String,
    pub approved_origins: Vec<String>,
    pub mcp_endpoint: String,
    pub callback: String,
    pub scope: Scope,
    pub token_response: String,
    pub identity: Identity,
    pub subject: Subject,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scope {
    pub required: Vec<String>,
    pub request_separator: String,
    pub response_separator: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    pub endpoint: String,
    pub method: String,
    pub response: String,
}

pub(super) use identity::verify;
pub(super) use token::decode;
pub(super) use validate::validate;

#[cfg(test)]
mod adverse;
