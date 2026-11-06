use super::{Prepared, input::Input, presentation};
use crate::{
    native::context::Context,
    native_authority::{
        Error, Result, contract,
        dispatch::Invocation,
        effective::{Approved, Snapshot},
    },
};
use serde_json::json;
use std::collections::BTreeMap;

type Eligible<'a> = BTreeMap<&'a str, &'a Approved>;
#[derive(Clone, Default, PartialEq, Eq, Debug)]
pub(in crate::native) struct Registry {
    handles: BTreeMap<String, Handle>,
    cursors: BTreeMap<String, Cursor>,
}
#[derive(Clone, PartialEq, Eq, Debug)]
struct Handle {
    name: String,
    digest: String,
    described: Option<String>,
}
#[derive(Clone, PartialEq, Eq, Debug)]
struct Cursor {
    query: String,
    limit: usize,
    offset: usize,
    inventory: String,
}
impl Registry {
    pub(super) fn prepare(
        &mut self,
        input: Input,
        eligible: &Eligible<'_>,
        snapshot: &Snapshot,
        context: &Context,
    ) -> Result<Prepared> {
        match input {
            Input::Search {
                query,
                limit,
                cursor,
            } => self
                .search(query, limit, cursor, eligible, snapshot)
                .map(Prepared::Local),
            Input::Describe(handle) => {
                let (reference, tool) = self.selected(&handle, eligible)?;
                let result = presentation::result(presentation::describe(&reference.name, tool))?;
                self.handles.get_mut(&handle).unwrap().described = Some(tool.digest.clone());
                Ok(Prepared::Local(result))
            }
            Input::Invoke {
                handle,
                digest,
                arguments,
            } => {
                let (reference, tool) = self.selected(&handle, eligible)?;
                if reference.described.as_deref() != Some(&digest) || tool.digest != digest {
                    return Err(Error("schema_required"));
                }
                Ok(Prepared::Invoke(Invocation {
                    agent: context.identity.public_id.clone(),
                    connection: context.name.clone(),
                    name: reference.name.clone(),
                    source: snapshot.current.source.clone(),
                    digest,
                    arguments,
                }))
            }
        }
    }
    fn selected<'a>(
        &self,
        handle: &str,
        eligible: &Eligible<'a>,
    ) -> Result<(&Handle, &'a Approved)> {
        let reference = self.handles.get(handle).ok_or(Error("compact_reference"))?;
        let tool = eligible
            .get(reference.name.as_str())
            .filter(|t| t.digest == reference.digest)
            .ok_or(Error("compact_reference"))?;
        Ok((reference, *tool))
    }
    fn search(
        &mut self,
        query: String,
        limit: usize,
        cursor: Option<String>,
        eligible: &Eligible<'_>,
        snapshot: &Snapshot,
    ) -> Result<serde_json::Value> {
        let inventory = contract::digest(
            "locksmith-compact-cursor-v1",
            &json!([
                snapshot.generation,
                snapshot.revision,
                eligible
                    .iter()
                    .map(|(n, t)| (*n, &t.digest))
                    .collect::<Vec<_>>()
            ]),
        );
        let offset = match cursor {
            None => 0,
            Some(key) => {
                let c = self.cursors.get(&key).ok_or(Error("compact_reference"))?;
                if c.query != query || c.limit != limit || c.inventory != inventory {
                    return Err(Error("compact_cursor_changed"));
                }
                c.offset
            }
        };
        let needle = query.trim().to_lowercase();
        let found = eligible
            .iter()
            .filter(|(_, t)| {
                ["name", "title", "description"].iter().any(|k| {
                    t.public[*k]
                        .as_str()
                        .is_some_and(|s| s.to_lowercase().contains(&needle))
                })
            })
            .collect::<Vec<_>>();
        let mut matches = Vec::new();
        for (name, tool) in found.iter().skip(offset).take(limit) {
            let handle = self.handle(name, &tool.digest)?;
            matches.push(json!({"handle":handle,"name":name,"contract_digest":tool.digest,"summary":presentation::summary(&tool.public),"signature":presentation::signature(&tool.public)}));
        }
        let next = offset + matches.len();
        let cursor = if next < found.len() {
            Some(self.cursor(Cursor {
                query,
                limit,
                offset: next,
                inventory,
            })?)
        } else {
            None
        };
        presentation::result(json!({"matches":matches,"next_cursor":cursor}))
    }
    fn handle(&mut self, name: &str, digest: &str) -> Result<String> {
        if let Some((key, _)) = self
            .handles
            .iter()
            .find(|(_, h)| h.name == name && h.digest == digest)
        {
            return Ok(key.clone());
        }
        if self.handles.len() >= 32 {
            return Err(Error("compact_capacity"));
        }
        let key = token(&self.handles)?;
        self.handles.insert(
            key.clone(),
            Handle {
                name: name.into(),
                digest: digest.into(),
                described: None,
            },
        );
        Ok(key)
    }
    fn cursor(&mut self, cursor: Cursor) -> Result<String> {
        if let Some((key, _)) = self.cursors.iter().find(|(_, c)| **c == cursor) {
            return Ok(key.clone());
        }
        if self.cursors.len() >= 32 {
            return Err(Error("compact_capacity"));
        }
        let key = token(&self.cursors)?;
        self.cursors.insert(key.clone(), cursor);
        Ok(key)
    }
}
fn token<T>(existing: &BTreeMap<String, T>) -> Result<String> {
    for _ in 0..8 {
        let mut bytes = [0u8; 16];
        getrandom::fill(&mut bytes).map_err(|_| Error("backend_unavailable"))?;
        let key = bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
        if !existing.contains_key(&key) {
            return Ok(key);
        }
    }
    Err(Error("backend_unavailable"))
}
