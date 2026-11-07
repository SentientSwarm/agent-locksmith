use super::{
    super::{Error, Result},
    Scope,
};
use serde_json::Value;
use std::collections::HashSet;

pub(super) fn valid_token(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|b| (0x21..=0x7e).contains(&b) && !b",\\\"".contains(&b))
}
impl Scope {
    pub(super) fn valid(&self) -> bool {
        !self.required.is_empty()
            && self.required.len() <= 32
            && self.required.iter().all(|s| valid_token(s))
            && self.required.iter().collect::<HashSet<_>>().len() == self.required.len()
            && ["space", "comma"].contains(&self.request_separator.as_str())
            && ["space", "comma", "space_or_comma"].contains(&self.response_separator.as_str())
    }
    pub(super) fn evidence(&self, v: Option<&Value>) -> Result<String> {
        let raw = v
            .and_then(Value::as_str)
            .filter(|s| s.len() <= 8192)
            .ok_or(Error("token_metadata_mismatch"))?;
        let fields = self.fields(raw)?;
        if fields.len() != self.required.len()
            || fields.iter().collect::<HashSet<_>>().len() != fields.len()
            || !self.required.iter().all(|s| fields.contains(&s.as_str()))
        {
            return Err(Error("token_metadata_mismatch"));
        }
        // Every emitted value was present in the response; declaration sets order only.
        Ok(self
            .required
            .iter()
            .map(|s| *fields.iter().find(|v| **v == s).unwrap())
            .collect::<Vec<_>>()
            .join(" "))
    }
    fn fields<'a>(&self, raw: &'a str) -> Result<Vec<&'a str>> {
        if !raw.is_ascii() || raw.bytes().any(|b| b.is_ascii_control()) {
            return Err(Error("token_metadata_mismatch"));
        }
        let mut out = Vec::new();
        for chunk in raw.split(',') {
            if self.response_separator == "space" && raw.contains(',') {
                return Err(Error("token_metadata_mismatch"));
            }
            let chunk = chunk.trim_matches(' ');
            if chunk.is_empty() {
                return Err(Error("token_metadata_mismatch"));
            }
            if self.response_separator == "comma" {
                out.push(chunk);
            } else {
                out.extend(chunk.split(' ').filter(|s| !s.is_empty()));
            }
        }
        if !out.iter().all(|s| valid_token(s)) {
            return Err(Error("token_metadata_mismatch"));
        }
        Ok(out)
    }
}
