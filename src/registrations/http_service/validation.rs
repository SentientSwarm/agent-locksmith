use super::{ContentType, Field, HttpService, Operation};
use std::collections::HashSet;

pub(super) fn valid(service: &HttpService) -> bool {
    let mut ids = HashSet::new();
    service.version == 1
        && !service.operations.is_empty()
        && service.operations.len() <= 32
        && service
            .operations
            .iter()
            .all(|op| text(&op.id, 64) && ids.insert(&op.id) && operation(op))
}

fn text(value: &str, max: usize) -> bool {
    !value.trim().is_empty() && value.len() <= max && !value.chars().any(char::is_control)
}

fn path(value: &str) -> bool {
    value.len() > 1
        && value.len() <= 2048
        && value.starts_with('/')
        && !value.starts_with("//")
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"/-._~".contains(&c))
        && value.split('/').all(|part| part != "." && part != "..")
}

fn fields(values: &[Field]) -> bool {
    let mut names = HashSet::new();
    values.len() <= 64
        && values.iter().all(|field| {
            text(&field.name, 128) && text(&field.description, 2048) && names.insert(&field.name)
        })
}

fn operation(op: &Operation) -> bool {
    text(&op.summary, 2048)
        && path(&op.path)
        && fields(&op.query)
        && fields(&op.response.fields)
        && (200..300).contains(&op.response.status)
        && op.errors.len() <= 32
        && op
            .errors
            .iter()
            .all(|e| (400..600).contains(&e.status) && text(&e.description, 2048))
        && op.request_body.as_ref().is_none_or(|b| fields(&b.fields))
        && match op.response.content_type {
            ContentType::Json => true,
            ContentType::Text => op.response.fields.is_empty() && op.example.response.is_string(),
        }
        && example(op)
}

fn example(op: &Operation) -> bool {
    let query = &op.example.query;
    query
        .keys()
        .all(|name| op.query.iter().any(|field| &field.name == name))
        && op
            .query
            .iter()
            .all(|field| !field.required || query.contains_key(&field.name))
        && match &op.request_body {
            Some(body) => !body.required || op.example.body.is_some(),
            None => op.example.body.is_none(),
        }
}
