//! Session-local compact references; all effects use the ordinary dispatcher.
mod input;
mod presentation;
mod registry;

use super::context::Context;
use crate::native_authority::{
    Result, control::Control, dispatch::Invocation, effective::Snapshot,
};
pub(super) use registry::Registry;
use serde_json::Value;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Facade {
    Standard,
    Compact,
}

pub(super) enum Prepared {
    Local(Value),
    Invoke(Invocation),
}

pub(super) fn list(context: &Context, snapshot: &Snapshot) -> Result<Vec<Value>> {
    fresh(snapshot)?;
    context.list(snapshot)?;
    Ok(presentation::tools())
}

pub(super) fn prepare(
    context: &Context,
    snapshot: &Snapshot,
    name: &str,
    args: Value,
    control: &Control,
) -> Result<Prepared> {
    let input = input::Input::parse(name, args)?;
    context.check_snapshot(snapshot)?;
    // Lock order is always pins then compact. No lock is held across an await.
    let pins = context.pins.lock().unwrap();
    let (source, names) = pins
        .0
        .as_ref()
        .ok_or(crate::native_authority::Error("tools_list_required"))?;
    snapshot.current.matches(source)?;
    let eligible = snapshot
        .tools
        .iter()
        .filter(|(n, t)| names.get(*n) == Some(&t.digest))
        .map(|(n, t)| (n.as_str(), t))
        .collect();
    let mut registry = context.compact.lock().unwrap();
    // Stage/render/check/publish under one lock: concurrent receipts cannot be lost.
    let mut staged = registry.clone();
    let prepared = staged.prepare(input, &eligible, snapshot, context)?;
    control.check()?;
    fresh(snapshot)?;
    *registry = staged;
    Ok(prepared)
}

fn fresh(snapshot: &Snapshot) -> Result<()> {
    if snapshot
        .expires_at
        .is_some_and(|t| t <= crate::native_authority::store::now())
    {
        return Err(crate::native_authority::Error("source_unavailable"));
    }
    if !snapshot.tools.is_empty() {
        snapshot.fresh()?;
    }
    Ok(())
}
